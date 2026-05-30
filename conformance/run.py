"""PIC Conformance Runner v0.1.

Executes the conformance vectors declared in ``conformance/manifest.json``
against the Python reference implementation and reports pass/fail.

First pass: canonicalization and core modes. Evidence mode added in v0.8.2
(see ``conformance/evidence/README.md``). Trust-sanitization mode added in
v0.8.2 (see ``conformance/trust_sanitization/README.md``).
Cross-implementation runners follow in subsequent v0.8.2 PRs per the v0.8.2
release plan; see ``ROADMAP.md`` §1.2.

Usage
-----
From the repo root::

    python -m conformance.run
    python -m conformance.run --manifest conformance/manifest.json
    python -m conformance.run --verbose
    python -m conformance.run --json
    python -m conformance.run --filter-mode evidence
    python -m conformance.run --filter-id canon-001-basic-object

Exit codes
----------
- 0  — all selected vectors passed (or empty manifest with no filter
       applied; see ``RunnerReport.all_passed``).
- 1  — at least one selected vector failed (manifest itself was valid).
- 2  — manifest was malformed, OR an explicit filter selected zero vectors.

Diagnostic taxonomy
-------------------
Per-vector failures and summary-level outcomes are tagged with one of the
eight tokens defined in the ``DC_*`` constants below (v0.8.2 PR V8.2-3
design checkpoint §3). ``--json`` output surfaces the per-vector token in
``results[].reason_code`` and the summary token in
``summary.diagnostic``. Human mode preserves the existing freeform
per-vector reason text and surfaces summary diagnostics such as
``no_vectors_selected`` in the diagnostic block.

Schema validation
-----------------
The runner rejects any manifest entry with fields outside the strict
whitelist for its ``(mode, expected)`` tuple, and any ``mode`` /
``expected`` combination not declared in the schema. ``expected_error_code``
(present on block entries for modes whose schema declares it) must be a
non-empty string starting with ``PIC_``; for ``trust_sanitization`` blocks
it MUST be exactly ``"PIC_VERIFIER_FAILED"``. ``matrix_id`` (present on
trust_sanitization entries) MUST be one of the 6 recognized matrix bases.
This strictness is deliberate: a typo in the manifest should surface as a
``ManifestError`` at runner startup, not as a silently-passing vector.

Manifest-vector consistency
---------------------------
Per-vector execution additionally checks that the vector file's internal
fields agree with the manifest entry (``id``, ``mode`` when declared or
required by the vector mode, ``expected``, and ``expected_error_code`` for
block vectors in modes that declare it). Drift between the manifest and
the file is reported as a vector-level failure with a ``manifest/vector
drift`` reason, not silently preferring one over the other.

For ``trust_sanitization`` mode, the runner additionally enforces
coordinate consistency: the vector ``id`` and manifest ``file`` MUST match
the expected forms derived from ``matrix_id`` + the boolean coordinates in
``options``. This prevents silent matrix corruption (a file named for one
cell but containing the options of another).

Filtering
---------
``--filter-mode <mode>`` (repeatable) and ``--filter-id <id>`` (repeatable)
select a subset of manifest entries to execute. Multiple flags of the same
kind UNION together, and the two kinds also union with each other — a
vector is selected if it matches ANY mode filter OR ANY id filter. When
neither flag is present, all vectors are selected. Unknown filter values
(unknown mode names, unknown ids) are not validated at argparse time;
they simply select nothing. An explicit filter that selects zero vectors
triggers ``summary.diagnostic="no_vectors_selected"`` and exit 2 — silent
CI passes on typo'd filter targets would be dangerous.

Warning handling
----------------
The runner suppresses exactly one known-transitional warning class —
``pic_standard.pipeline.PICTrustFutureWarning`` — around the
``verify_proposal()`` call for core-mode, evidence-mode, and
trust_sanitization-mode vectors. Per ``conformance/core/README.md``,
warnings are language-specific and out of scope for shared portable
vectors; leaving this particular warning unsuppressed would produce noise
in CI logs during passing runs of ``core-allow-002-trusted-money`` and
similar legacy-trust / evidence / trust-sanitization vectors. All other
warning classes are left unfiltered so that a future regression surfacing
as a ``DeprecationWarning``, ``ResourceWarning``, or ``RuntimeWarning`` is
still visible to reviewers.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

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

VALID_MODES = {"canonicalization", "core", "evidence", "trust_sanitization"}

EXPECTED_BY_MODE: Dict[str, set] = {
    "canonicalization": {"canonical_match"},
    "core": {"allow", "block"},
    "evidence": {"allow", "block"},
    "trust_sanitization": {"allow", "block"},
}

MANIFEST_TOP_FIELDS = {"version", "vectors"}

# Recognized trust-sanitization matrix bases. These correspond 1:1 to the
# proposal bases in tests/test_trust_deprecation_warning.py::
# VERDICT_REGRESSION_MATRIX. Manifest entries with mode="trust_sanitization"
# MUST declare a matrix_id from this set; arbitrary strings are rejected at
# manifest validation time.
TRUST_SANITIZATION_MATRIX_IDS = {
    "compute_risk",
    "read_only_query",
    "financial_hash_ok",
    "financial_irreversible",
    "privacy_risk",
    "robotic_action",
}

# Exact fields allowed on a manifest vector entry, keyed by (mode, expected).
# Anything outside the declared set triggers ManifestError.
# Note: evidence-mode and trust_sanitization-mode vector-internal fields
# (``options`` and ``proposal``) live in the vector file, NOT the manifest
# entry. ``embedded_keyring`` is evidence-mode only and is rejected for
# trust_sanitization vectors. ``matrix_id`` is a trust_sanitization-only
# manifest field that groups vectors by the proposal-base they were lifted
# from in tests/test_trust_deprecation_warning.py::VERDICT_REGRESSION_MATRIX.
ENTRY_FIELDS: Dict[tuple, set] = {
    ("canonicalization", "canonical_match"): {"id", "file", "mode", "expected"},
    ("core", "allow"): {"id", "file", "mode", "expected"},
    ("core", "block"): {"id", "file", "mode", "expected", "expected_error_code"},
    ("evidence", "allow"): {"id", "file", "mode", "expected"},
    ("evidence", "block"): {"id", "file", "mode", "expected", "expected_error_code"},
    ("trust_sanitization", "allow"): {"id", "file", "mode", "expected", "matrix_id"},
    ("trust_sanitization", "block"): {
        "id",
        "file",
        "mode",
        "expected",
        "expected_error_code",
        "matrix_id",
    },
}


# ---------------------------------------------------------------------------
# Diagnostic taxonomy (v0.8.2 PR V8.2-3 commit 3, design checkpoint §3)
# ---------------------------------------------------------------------------
#
# The eight-token taxonomy is the stable surface that machine consumers
# (CI gates, dashboards, the v0.9.0 TS verifier's parity tests) match on.
# Freeform per-result detail lives in ``VectorResult.reason`` (carried
# into JSON output's ``results[].message``); the category lives in
# ``VectorResult.reason_code`` (carried into ``results[].reason_code``).
# Splitting code from prose keeps the contract small while preserving
# debuggability.
#
# Six tokens are per-result. Two tokens are summary-only.
#
# Per-result tokens (VectorResult.reason_code):

# Verifier returned allow/block different from the vector's ``expected``.
DC_VERDICT_MISMATCH = "verdict_mismatch"

# Block verdict happened, but error code differed from ``expected_error_code``.
DC_ERROR_CODE_MISMATCH = "error_code_mismatch"

# Canonical bytes or canonical SHA-256 mismatch on a canonicalization vector.
DC_CANONICALIZATION_MISMATCH = "canonicalization_mismatch"

# Manifest valid but points at wrong/missing vector file, or vector inline
# id/mode/expected/expected_error_code/coordinate disagrees with the
# manifest entry. NOT for malformed manifest JSON — that is
# ``DC_MANIFEST_INVALID`` (summary-only).
DC_MANIFEST_DRIFT = "manifest_drift"

# Vector file exists and parses but violates a runner/vector guard shape:
# missing options, wrong option types, forbidden ``embedded_keyring`` in
# trust_sanitization mode, sig evidence in trust_sanitization mode, bad
# ``evidence_root_dir``, ``PipelineOptions(**options)`` construction
# failure, etc. Authoring/shape errors at the vector level.
DC_VECTOR_INVALID = "vector_invalid"

# Unexpected exception caught at the dispatch boundary (``canonicalize()``
# or ``verify_proposal()`` raised). Genuine "this should not normally
# happen" bucket; narrow in practice after commit 3 re-categorized
# ``PipelineOptions`` construction failures to ``DC_VECTOR_INVALID``.
DC_RUNNER_ERROR = "runner_error"

# Summary-only tokens (RunnerReport.diagnostic / JSON summary.diagnostic):

# Explicit --filter-mode / --filter-id selected zero vectors. Surfaces as
# ``summary.diagnostic`` + exit 2.
DC_NO_VECTORS_SELECTED = "no_vectors_selected"

# Manifest parse / top-level schema / entry validation failed before any
# vectors could be selected or executed. Surfaces via
# ``JsonRenderer.render_manifest_error`` (commit 2) — the
# ``ManifestError`` exception short-circuits before a ``RunnerReport`` is
# built, so this token never appears on a ``RunnerReport.diagnostic``
# field, only on the manifest-error JSON envelope.
DC_MANIFEST_INVALID = "manifest_invalid"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class Selection:
    """Filter state + manifest size, populated by :func:`run_manifest`.

    ``total_in_manifest`` reflects the full manifest (pre-filter) count;
    ``selected`` is the count after filter application. Empty
    ``filter_modes`` AND empty ``filter_ids`` means "no filter applied" —
    in that case ``selected == total_in_manifest``.
    """

    total_in_manifest: int
    selected: int
    filter_modes: List[str] = field(default_factory=list)
    filter_ids: List[str] = field(default_factory=list)


@dataclass
class VectorResult:
    """Outcome of running a single manifest vector.

    ``reason_code`` is populated for failing vectors from the 8-token
    diagnostic taxonomy (``DC_*`` constants). Passing vectors leave
    ``reason_code`` as ``None`` (the contract: ``reason_code is None
    iff passed``). The freeform ``reason`` carries the human-readable
    detail that surfaces in JSON output's ``results[].message`` field
    and in indented human-mode failure output.
    """

    id: str
    mode: str
    passed: bool
    reason: str = ""
    reason_code: Optional[str] = None


@dataclass
class RunnerReport:
    """Aggregate outcome of running a manifest.

    Additions in v0.8.2 PR V8.2-3 commit 3:

      - ``selection``: filter state + manifest size, populated by
        :func:`run_manifest`. Default-constructed value is
        ``Selection(total_in_manifest=0, selected=0)`` so external
        callers building a RunnerReport by hand don't have to know
        about the new field.
      - ``diagnostic`` / ``message``: summary-level diagnostic token +
        freeform detail. Currently only set to
        ``DC_NO_VECTORS_SELECTED`` when filters select zero vectors.
        Manifest-level errors flow through :exc:`ManifestError` and
        never reach this field; ``DC_MANIFEST_INVALID`` lives on the
        JSON manifest-error envelope.
      - ``failed_count`` / ``exit_code`` properties: single sources of
        truth that both renderers and ``main()`` consume.
      - ``all_passed`` lock changed (design checkpoint §5): now
        ``failed_count == 0 AND diagnostic is None``. Empty manifest
        with no filter applied → ``all_passed=True``, ``exit_code=0``
        (vacuous success). Previously ``all_passed`` was
        ``total_count > 0 AND passed == total``.
    """

    manifest_version: str
    results: List[VectorResult] = field(default_factory=list)
    selection: Selection = field(default_factory=lambda: Selection(0, 0))
    diagnostic: Optional[str] = None
    message: Optional[str] = None

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def total_count(self) -> int:
        return len(self.results)

    @property
    def failed_count(self) -> int:
        return self.total_count - self.passed_count

    @property
    def all_passed(self) -> bool:
        return self.failed_count == 0 and self.diagnostic is None

    @property
    def exit_code(self) -> int:
        """Process exit code, derived from report state.

        Single source of truth: ``JsonRenderer`` puts this in the
        envelope's ``exit_code`` field, ``main()`` returns it. Per
        design checkpoint §5:

          - ``diagnostic == "no_vectors_selected"`` → 2
          - ``diagnostic == "manifest_invalid"``    → 2 (defensive;
            this case actually flows through ``ManifestError`` and
            never reaches a RunnerReport instance, but the mapping is
            included for completeness in case future code paths
            populate the field)
          - ``failed_count > 0``                    → 1
          - otherwise                                → 0
        """
        if self.diagnostic in (DC_NO_VECTORS_SELECTED, DC_MANIFEST_INVALID):
            return 2
        return 0 if self.failed_count == 0 else 1

    def format_summary(self, verbose: bool = False) -> str:
        """Back-compat shim that delegates to :class:`HumanRenderer`.

        Preserves the v0.8.2 PR V8.2-2 API surface for any out-of-repo or
        internal caller that imports ``RunnerReport`` and calls
        ``format_summary()`` directly. New code SHOULD construct a
        :class:`HumanRenderer` (or any other :class:`Renderer`
        implementation) and call :meth:`Renderer.render_report` instead.

        Output is byte-identical to
        ``HumanRenderer().render_report(self, verbose=verbose)`` — the
        runner CLI uses :class:`HumanRenderer` directly via
        :func:`main`; this shim exists purely to avoid breaking external
        callers across the v0.8.2 PR V8.2-3 commit-1 refactor boundary.

        Deprecation timeline: this shim may be removed in a future major
        version once external usage is confirmed nil. No deprecation
        warning is emitted in v0.8.2 to keep the refactor truly
        behavior-preserving at the CLI surface.
        """
        return HumanRenderer().render_report(self, verbose=verbose)


class ManifestError(Exception):
    """Raised when the manifest itself is malformed or contains invalid entries."""


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------
#
# v0.8.2 PR V8.2-3 commit 1 introduces a Renderer seam so subsequent commits
# can add machine-readable output modes (--json in commit 2) and operator
# filters (--filter-mode / --filter-id in commit 3) without re-touching the
# orchestrator or CLI entry point. Commit 1 is behavior-preserving: the
# default invocation produces byte-identical stdout to the v0.8.2 PR V8.2-2
# baseline (RunnerReport.format_summary semantics, moved verbatim into
# HumanRenderer.render_report; RunnerReport.format_summary is kept as a
# delegating compatibility shim).
#
# Commit 2 adds JsonRenderer for --json output mode and extends the
# Renderer protocol with render_manifest_error so both renderer
# implementations can surface manifest-load failures through their
# declared output format. main() chooses the renderer and routes both
# the success path (render_report) and the ManifestError path
# (render_manifest_error) through it. Human mode keeps writing
# ManifestError to stderr; JSON mode writes the manifest-error envelope
# from PR V8.2-3 design checkpoint §2 to stdout (JSON consumers parse a
# single stream).
#
# Commit 3 (this commit) adds filter-aware selection plumbing + the
# 8-token diagnostic taxonomy + summary.diagnostic /
# summary.message for the no_vectors_selected case. results[].reason_code
# is now populated (commits 1+2 left it null pending this commit's
# taxonomy work). The JsonRenderer carries a defensive fallback for the
# reason_code and message fields per the design lock: a failing vector
# without an explicit reason_code defaults to DC_RUNNER_ERROR, and
# without a reason defaults to "failed without message". Each failure
# site in run.py sets both explicitly; the fallback is the safety net
# for future drift.


class Renderer(Protocol):
    """Output renderer protocol for the conformance runner.

    Two operations:

      - :meth:`render_report` for a populated :class:`RunnerReport`
        (success path, vector failures, and the no_vectors_selected
        diagnostic).
      - :meth:`render_manifest_error` for the manifest-load failure
        path, which short-circuits before any RunnerReport is built.

    The protocol is the seam on which the v0.8.2 PR V8.2-3 follow-up
    commits build:

      - Commit 2 added JsonRenderer + render_manifest_error.
      - Commit 3 added selection plumbing + 8-token taxonomy +
        no_vectors_selected diagnostic. JsonRenderer surfaces the
        per-vector token in ``results[].reason_code`` and the summary
        token in ``summary.diagnostic``; HumanRenderer keeps the
        existing freeform per-vector reason text and renders summary
        diagnostics in a dedicated block.
    """

    def render_report(self, report: RunnerReport, *, verbose: bool) -> str:
        """Return a string representation of ``report`` for printing.

        The returned string does NOT include a trailing newline; the
        caller's ``print()`` supplies it. Matches the v0.8.2 PR V8.2-2
        ``RunnerReport.format_summary()`` contract.
        """
        ...

    def render_manifest_error(
        self,
        message: str,
        *,
        manifest_version: Optional[str] = None,
    ) -> str:
        """Render a manifest-error envelope/message.

        Implementations decide the format: :class:`HumanRenderer`
        returns the freeform ``"ManifestError: <message>"`` string that
        v0.8.2 PR V8.2-2 wrote to stderr; :class:`JsonRenderer` returns
        the JSON manifest-error envelope from PR V8.2-3 design
        checkpoint §2.

        ``manifest_version`` is populated by the caller iff it was
        readable before the validation failure point. The human form
        ignores it; the JSON form surfaces it as ``manifest_version``
        (else ``null``).
        """
        ...


class HumanRenderer:
    """Default human-readable text renderer.

    Default-invocation output (no filters, no diagnostic) is
    byte-identical to v0.8.2 PR V8.2-2 ``RunnerReport.format_summary()``
    — see the per-commit SHA256 verification gate.

    Format:

      - Header block: runner name, manifest version, total vector
        count, blank line.
      - One line per vector: ``  {PASS|FAIL}  {id}``.
      - Indented (8-space) reason lines on failure, or when
        ``verbose=True`` AND the result carries a non-empty ``reason``
        string.
      - Blank line.
      - Final ``Summary: X/Y passed`` line; suffix ``(Z failed)`` when
        not all vectors passed.

    Format extensions over commit 2:

      - When ``report.selection`` carries non-empty filter values, the
        header gains ``Filter modes:`` and/or ``Filter ids:`` lines
        and a ``Selected: X of Y`` line. Default invocation skips this
        block entirely (preserves the byte-identical SHA).
      - When ``report.diagnostic`` is set (currently only
        ``"no_vectors_selected"``), the per-vector block is replaced
        with a ``Diagnostic: <token>`` line + indented ``message`` and
        a one-line summary ``Summary: 0 vectors selected by filter``.

    Manifest-error form (added in commit 2) returns the byte-identical
    ``"ManifestError: <message>"`` string that v0.8.2 PR V8.2-2 wrote
    to stderr; :func:`main` continues to send it to stderr in human
    mode.
    """

    def render_report(self, report: RunnerReport, *, verbose: bool) -> str:
        lines = [
            "PIC Conformance Runner v0.1",
            f"Manifest version: {report.manifest_version}",
            f"Vectors:          {report.total_count}",
        ]

        # Filter header — surfaces only when filters were applied.
        # Default no-filter invocations skip this block, preserving the
        # byte-identical output across commits 1, 2, and 3.
        if report.selection.filter_modes or report.selection.filter_ids:
            if report.selection.filter_modes:
                lines.append(f"Filter modes:     {report.selection.filter_modes}")
            if report.selection.filter_ids:
                lines.append(f"Filter ids:       {report.selection.filter_ids}")
            lines.append(
                f"Selected:         {report.selection.selected} of "
                f"{report.selection.total_in_manifest}"
            )

        lines.append("")

        # Diagnostic short-circuit (no_vectors_selected). No per-vector
        # results to iterate; render the diagnostic block and a one-line
        # summary, then return.
        if report.diagnostic is not None:
            lines.append(f"Diagnostic: {report.diagnostic}")
            if report.message:
                for ml in report.message.splitlines():
                    lines.append(f"        {ml}")
            lines.append("")
            lines.append("Summary: 0 vectors selected by filter")
            return "\n".join(lines)

        # Normal per-vector block — unchanged behavior from commits 1+2.
        for r in report.results:
            status = "PASS" if r.passed else "FAIL"
            lines.append(f"  {status}  {r.id}")
            if (not r.passed or verbose) and r.reason:
                for line in r.reason.splitlines():
                    lines.append(f"        {line}")
        lines.append("")
        if report.all_passed:
            lines.append(f"Summary: {report.passed_count}/{report.total_count} passed")
        else:
            failed = report.failed_count
            lines.append(
                f"Summary: {report.passed_count}/{report.total_count} passed ({failed} failed)"
            )
        return "\n".join(lines)

    def render_manifest_error(
        self,
        message: str,
        *,
        manifest_version: Optional[str] = None,
    ) -> str:
        """Render a manifest-error message in human-readable form.

        Output is byte-identical to the v0.8.2 PR V8.2-2 stderr message
        ``"ManifestError: <message>"``. The ``manifest_version``
        parameter is accepted for protocol parity with
        :class:`JsonRenderer` but intentionally not surfaced — the human
        form has nowhere to expose it without breaking the
        byte-identical guarantee.
        """
        del manifest_version
        return f"ManifestError: {message}"


class JsonRenderer:
    """JSON output renderer for the conformance runner.

    Emits the JSON document defined in v0.8.2 PR V8.2-3 design checkpoint
    §2. Output is pretty-printed (2-space indent) to stdout. The
    renderer is the sole producer of output when ``--json`` is set;
    ``--verbose`` is accepted but has no effect (JSON always carries
    full per-vector detail).

    Defensive fallbacks for failing vectors per the design lock:

      - ``results[].reason_code``: a failing vector without an explicit
        ``reason_code`` defaults to :data:`DC_RUNNER_ERROR` rather than
        leaking a schema-violating null.
      - ``results[].message``: a failing vector without an explicit
        ``reason`` defaults to ``"failed without message"`` rather than
        leaking a schema-violating null.

    Both are last-resort safety nets — each failure site in
    :mod:`conformance.run` sets both fields explicitly. The fallbacks
    catch future drift if a contributor adds a failure site and forgets
    a keyword.

    Manifest-error envelope ``summary.message`` is rendered as
    ``"ManifestError: <message>"`` — the same prefix
    :class:`HumanRenderer` uses for stderr. The prefix is part of the
    locked PR V8.2-3 design checkpoint §2 shape so JSON consumers and
    humans see the same error string format.
    """

    def render_report(self, report: RunnerReport, *, verbose: bool) -> str:
        # verbose is accepted for Renderer protocol parity but ignored:
        # JSON output always carries full per-vector detail.
        del verbose
        results_json: List[Dict[str, Any]] = []
        for r in report.results:
            if r.passed:
                rc: Optional[str] = None
                msg: Optional[str] = None
            else:
                # Defensive fallbacks per design lock: passed=False with
                # a missing reason_code defaults to DC_RUNNER_ERROR, and
                # a missing reason defaults to "failed without message".
                # Both keep the JSON schema-valid (reason_code/message
                # non-null iff passed:false) even if a future failure
                # site forgets a keyword. Each existing failure site
                # sets both fields explicitly; these are safety nets.
                rc = r.reason_code or DC_RUNNER_ERROR
                msg = r.reason or "failed without message"
            results_json.append(
                {
                    "id": r.id,
                    "mode": r.mode,
                    "passed": r.passed,
                    "reason_code": rc,
                    "message": msg,
                }
            )
        envelope: Dict[str, Any] = {
            "manifest_version": report.manifest_version,
            "selection": {
                "total_in_manifest": report.selection.total_in_manifest,
                "selected": report.selection.selected,
                "filter_modes": list(report.selection.filter_modes),
                "filter_ids": list(report.selection.filter_ids),
            },
            "results": results_json,
            "summary": {
                "total": report.total_count,
                "passed": report.passed_count,
                "failed": report.failed_count,
                "all_passed": report.all_passed,
                "diagnostic": report.diagnostic,
                "message": report.message,
            },
            "exit_code": report.exit_code,
        }
        return json.dumps(envelope, indent=2)

    def render_manifest_error(
        self,
        message: str,
        *,
        manifest_version: Optional[str] = None,
    ) -> str:
        """Render the JSON manifest-error envelope per design checkpoint §2.

        ``manifest_version`` may be populated if the manifest's top-level
        ``version`` field was readable before the validation failure
        point; otherwise ``None``. In commit 2 the runner always passes
        ``None`` (no fine-grained "we got past version parsing" signal
        from :func:`_validate_manifest`); commit 3 preserves this — if
        the differentiation becomes useful for operators it can be
        refined in a later PR.

        ``summary.message`` is rendered with the ``"ManifestError: "``
        prefix — same as the :class:`HumanRenderer` stderr form — per
        the PR V8.2-3 design checkpoint §2 lock. JSON consumers and
        humans observe the same error string format.

        Selection is reported as zero/empty because manifest validation
        failed before filter resolution. Operator-passed filter
        arguments are intentionally not reflected here — the envelope's
        purpose is to surface the parse/schema failure, not the
        operator's filter intent. The freeform ``message`` carries the
        failure detail.
        """
        envelope: Dict[str, Any] = {
            "manifest_version": manifest_version,
            "selection": {
                "total_in_manifest": 0,
                "selected": 0,
                "filter_modes": [],
                "filter_ids": [],
            },
            "results": [],
            "summary": {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "all_passed": False,
                "diagnostic": DC_MANIFEST_INVALID,
                "message": f"ManifestError: {message}",
            },
            "exit_code": 2,
        }
        return json.dumps(envelope, indent=2)


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

    # `expected_error_code` general validation: any (mode, expected) whose
    # ENTRY_FIELDS schema includes the field requires a non-empty PIC_* string.
    if "expected_error_code" in allowed_fields:
        ec = entry["expected_error_code"]
        if not isinstance(ec, str) or not ec.startswith("PIC_"):
            raise ManifestError(
                f"expected_error_code must be a non-empty string starting with 'PIC_', got {ec!r}"
            )

    # `matrix_id` general validation: any (mode, expected) whose ENTRY_FIELDS
    # schema includes the field requires a non-empty string.
    if "matrix_id" in allowed_fields:
        mid = entry["matrix_id"]
        if not isinstance(mid, str) or not mid:
            raise ManifestError(f"matrix_id must be a non-empty string, got {mid!r}")

    # Trust-sanitization-specific tightening:
    # 1. matrix_id MUST be one of the 6 recognized matrix bases.
    # 2. block entries MUST use exactly PIC_VERIFIER_FAILED — the matrix's
    #    contract is that all trust-sanitization blocks are verifier-layer
    #    blocks. Any other error code is an authoring mistake.
    if mode == "trust_sanitization":
        if entry["matrix_id"] not in TRUST_SANITIZATION_MATRIX_IDS:
            raise ManifestError(
                f"matrix_id {entry['matrix_id']!r} is not a recognized trust-sanitization "
                f"matrix base (allowed: {sorted(TRUST_SANITIZATION_MATRIX_IDS)})"
            )
        if expected == "block" and entry["expected_error_code"] != "PIC_VERIFIER_FAILED":
            raise ManifestError(
                "trust_sanitization block entries must use "
                "expected_error_code='PIC_VERIFIER_FAILED', got "
                f"{entry['expected_error_code']!r}"
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

    Applies to core-mode, evidence-mode, and trust_sanitization-mode vectors
    (all three carry `expected` and optionally `expected_error_code` inside
    the vector file). Canonicalization vector files do not carry duplicate
    `expected` / `expected_error_code` fields, so there is nothing to
    cross-check at that layer beyond the id.

    Mode drift (v0.8.2+):
      - If a vector file declares `mode` and it disagrees with the manifest
        entry's `mode`, that is drift regardless of which mode is declared.
        This generic check runs for ALL modes — a canonicalization vector
        with a wrong `mode` declaration would still drift.
      - Evidence-mode vector files MUST declare `mode: "evidence"` per
        ``conformance/evidence/README.md``. Trust_sanitization-mode vector
        files MUST declare `mode: "trust_sanitization"` per
        ``conformance/trust_sanitization/README.md``. Existing core-mode
        vector files do NOT declare `mode` and are not required to;
        backward compat preserved.
    """
    mode = entry["mode"]

    # Generic declared-mode mismatch check — runs for ALL modes, before the
    # canonicalization early-return below. Catches canonicalization vectors
    # that declare a stale or wrong `mode` value internally.
    if "mode" in vec and vec["mode"] != entry["mode"]:
        return f"'mode' mismatch: manifest={entry['mode']!r} file={vec['mode']!r}"

    if mode not in ("core", "evidence", "trust_sanitization"):
        return None

    # Evidence-mode vector files MUST declare `mode: "evidence"` explicitly.
    # (Core-mode vector files MAY omit `mode`; the generic check above lets
    # them through as long as no wrong `mode` is declared.)
    if mode == "evidence" and vec.get("mode") != "evidence":
        return "evidence vector file must declare mode='evidence'"

    # Trust_sanitization-mode vector files MUST declare
    # `mode: "trust_sanitization"` explicitly.
    if mode == "trust_sanitization" and vec.get("mode") != "trust_sanitization":
        return "trust_sanitization vector file must declare mode='trust_sanitization'"

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
# Filter resolution (v0.8.2 PR V8.2-3 commit 3)
# ---------------------------------------------------------------------------


def _apply_filters(
    entries: List[Dict[str, Any]],
    *,
    filter_modes: Optional[List[str]],
    filter_ids: Optional[List[str]],
) -> List[Dict[str, Any]]:
    """Return entries selected by the union of mode + id filters.

    Semantics (design checkpoint §1, §4):

      - No filters set → all entries returned (default behavior).
      - One or more ``--filter-mode`` flags → set of allowed modes.
      - One or more ``--filter-id`` flags → set of allowed ids.
      - When BOTH filter kinds are present, an entry is selected if its
        mode is in ``filter_modes`` OR its id is in ``filter_ids``
        (union across kinds; rationale per §1: union avoids the
        common-case foot-gun where ``--filter-mode evidence
        --filter-id canon-001-basic-object`` produces an empty
        intersection).
      - Unknown mode names and unknown ids are not validated here; they
        simply select nothing. The empty-selection-with-non-empty-filters
        case is detected by :func:`run_manifest` and surfaces as
        ``summary.diagnostic="no_vectors_selected"`` + exit 2.
    """
    fmodes = set(filter_modes or [])
    fids = set(filter_ids or [])
    if not fmodes and not fids:
        return list(entries)
    return [e for e in entries if e["mode"] in fmodes or e["id"] in fids]


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
            reason_code=DC_VECTOR_INVALID,
        )

    try:
        actual_bytes = canonicalize(input_value)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="canonicalization",
            passed=False,
            reason=f"canonicalize() raised {type(e).__name__}: {e}",
            reason_code=DC_RUNNER_ERROR,
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
            reason_code=DC_CANONICALIZATION_MISMATCH,
        )

    actual_sha = hashlib.sha256(actual_bytes).hexdigest()
    if actual_sha != expected_sha:
        return VectorResult(
            id=vid,
            mode="canonicalization",
            passed=False,
            reason=(f"SHA-256 mismatch\n  expected: {expected_sha}\n  actual:   {actual_sha}"),
            reason_code=DC_CANONICALIZATION_MISMATCH,
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
            reason_code=DC_VECTOR_INVALID,
        )

    proposal = vec["proposal"]
    options_dict = vec.get("options", {})

    # Defensive type guard, parallel to evidence/trust_sanitization modes.
    # Without this, PipelineOptions construction or verify_proposal would
    # leak an AttributeError / TypeError on non-dict proposals (e.g. list,
    # string). Fail-closed with a clear reason instead.
    if not isinstance(proposal, dict):
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason="vector file field 'proposal' must be an object",
            reason_code=DC_VECTOR_INVALID,
        )

    try:
        options = PipelineOptions(**options_dict)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason=f"could not construct PipelineOptions: {type(e).__name__}: {e}",
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_RUNNER_ERROR,
        )

    if entry["expected"] == "allow":
        if result.ok:
            return VectorResult(id=vid, mode="core", passed=True)
        code = result.error.code.value if (result.error and result.error.code) else "<none>"
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason=f"expected allow but got block ({code})",
            reason_code=DC_VERDICT_MISMATCH,
        )

    # expected == "block"
    if result.ok:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason="expected block but proposal was allowed",
            reason_code=DC_VERDICT_MISMATCH,
        )
    if result.error is None or result.error.code is None:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason="expected block with error code, got block with no error code",
            reason_code=DC_ERROR_CODE_MISMATCH,
        )
    actual_code = result.error.code.value
    expected_code = entry["expected_error_code"]
    if actual_code != expected_code:
        return VectorResult(
            id=vid,
            mode="core",
            passed=False,
            reason=f"expected {expected_code} but got {actual_code}",
            reason_code=DC_ERROR_CODE_MISMATCH,
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
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_VECTOR_INVALID,
        )

    if options_dict.get("verify_evidence") is not True:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="evidence vector must set options.verify_evidence=true",
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_VECTOR_INVALID,
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
                reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_VECTOR_INVALID,
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
            reason_code=DC_RUNNER_ERROR,
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
            reason_code=DC_VERDICT_MISMATCH,
        )

    # expected == "block"
    if result.ok:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="expected block but proposal was allowed",
            reason_code=DC_VERDICT_MISMATCH,
        )
    if result.error is None or result.error.code is None:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason="expected block with error code, got block with no error code",
            reason_code=DC_ERROR_CODE_MISMATCH,
        )
    actual_code = result.error.code.value
    expected_code = entry["expected_error_code"]
    if actual_code != expected_code:
        return VectorResult(
            id=vid,
            mode="evidence",
            passed=False,
            reason=f"expected {expected_code} but got {actual_code}",
            reason_code=DC_ERROR_CODE_MISMATCH,
        )
    return VectorResult(id=vid, mode="evidence", passed=True)


# ---------------------------------------------------------------------------
# Trust-sanitization-mode dispatch (v0.8.2 PR V8.2-2)
# ---------------------------------------------------------------------------


def _run_trust_sanitization_vector(vec: Dict[str, Any], entry: Dict[str, Any]) -> VectorResult:
    """Run a trust-sanitization-mode vector through verify_proposal().

    Parallel structure to `_run_evidence_vector` but tuned for the
    trust-sanitization conformance surface (see
    ``conformance/trust_sanitization/README.md``):

      - The vector's `options` MUST declare both `strict_trust` and
        `verify_evidence` explicitly AS JSON BOOLEANS. The matrix
        coordinate is encoded in these options; defaults or stringly-typed
        values would make the vector ambiguous.
      - Rejects `key_resolver` and `proposal_base_dir` in options (same
        portability principle as evidence mode — runner-controlled fields
        cannot be smuggled through JSON).
      - Rejects non-dict `proposal` values fail-closed.
      - Trust-sanitization vectors MUST NOT carry sig evidence (the
        regression matrix excludes financial_sig_ok.json). The runner
        rejects sig-evidence proposals fail-closed in this mode to prevent
        falling back to PIC_KEYS_PATH / default keyring resolution.
        Authors who need sig-evidence coverage should use evidence mode.
      - Rejects top-level `embedded_keyring`. In this mode it would be
        silently ignored (no sig evidence), which would mislead reviewers
        about hermeticity.
      - Enforces coordinate consistency: the vector `id` and manifest
        `file` MUST be derivable from `matrix_id` + the boolean
        coordinates. Catches silent matrix corruption (a file named for
        one cell but containing the options of another).
      - Reuses the evidence-mode helpers for `evidence_root_dir`
        resolution and `proposal_base_dir` derivation. This matters for
        the `financial_hash_ok` matrix cells which contain file-backed
        hash evidence; other matrix cells (low-impact,
        self-asserted-trusted high-impact) have no evidence and the
        resolution is a no-op.
      - Suppresses PICTrustFutureWarning around the verify_proposal call
        (same as core/evidence modes).
    """
    vid = vec["id"]
    if "proposal" not in vec:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="vector file missing required field: 'proposal'",
            reason_code=DC_VECTOR_INVALID,
        )

    # Options must be present as an object. The matrix coordinate
    # (strict_trust, verify_evidence) is mandatory; relying on defaults
    # would make the vector ambiguous about which cell it tests.
    if "options" not in vec or not isinstance(vec["options"], dict):
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="trust_sanitization vector missing required object field: 'options'",
            reason_code=DC_VECTOR_INVALID,
        )

    options_dict = vec["options"]

    # Require both matrix-axis settings to be present (no implicit defaults).
    if "strict_trust" not in options_dict:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="trust_sanitization vector must declare options.strict_trust",
            reason_code=DC_VECTOR_INVALID,
        )
    if "verify_evidence" not in options_dict:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="trust_sanitization vector must declare options.verify_evidence",
            reason_code=DC_VECTOR_INVALID,
        )

    # Both matrix axes MUST be actual booleans. JSON true/false → Python bool.
    # Without this guard, a stringly-typed "false" or numeric 0 would pass
    # the presence check above and silently represent a matrix coordinate
    # the vector did not actually intend.
    if not isinstance(options_dict["strict_trust"], bool):
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="trust_sanitization vector options.strict_trust must be boolean",
            reason_code=DC_VECTOR_INVALID,
        )
    if not isinstance(options_dict["verify_evidence"], bool):
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="trust_sanitization vector options.verify_evidence must be boolean",
            reason_code=DC_VECTOR_INVALID,
        )

    # Reject smuggling of runner-controlled fields (same convention as
    # evidence mode).
    if "key_resolver" in options_dict:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="trust_sanitization vector options must not declare key_resolver",
            reason_code=DC_VECTOR_INVALID,
        )
    if "proposal_base_dir" in options_dict:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=(
                "trust_sanitization vector options must not declare proposal_base_dir; "
                "the runner derives it from evidence_root_dir"
            ),
            reason_code=DC_VECTOR_INVALID,
        )

    # Coordinate consistency check: the vector id and manifest file path
    # MUST be derivable from matrix_id + boolean coordinates. Catches a real
    # silent-corruption foot-gun: a file named compute_risk__strict-f__verify-f.json
    # containing strict_trust=true would silently test the wrong matrix
    # cell. Low-impact rows hide this (all 4 cells = allow) but high-impact
    # rows would flip a real verdict.
    strict_label = "t" if options_dict["strict_trust"] else "f"
    verify_label = "t" if options_dict["verify_evidence"] else "f"
    matrix_id = entry["matrix_id"]
    expected_id = f"trust-{matrix_id}-strict-{strict_label}-verify-{verify_label}"
    expected_file = (
        f"trust_sanitization/{matrix_id}__strict-{strict_label}__verify-{verify_label}.json"
    )
    if vec["id"] != expected_id:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=(
                f"coordinate/id mismatch: options imply id={expected_id!r}, "
                f"vector file declares id={vec['id']!r}"
            ),
            reason_code=DC_VECTOR_INVALID,
        )
    if entry["file"] != expected_file:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=(
                f"coordinate/file mismatch: options imply file={expected_file!r}, "
                f"manifest declares file={entry['file']!r}"
            ),
            reason_code=DC_VECTOR_INVALID,
        )

    # Reject top-level embedded_keyring. In this mode it would be silently
    # ignored (no sig evidence), which would mislead reviewers into thinking
    # keyring hermeticity is being enforced. Authors who need sig-evidence
    # coverage with an embedded keyring should use evidence mode.
    if "embedded_keyring" in vec:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=(
                "trust_sanitization vectors must not declare embedded_keyring; "
                "use evidence mode for signature-evidence conformance"
            ),
            reason_code=DC_VECTOR_INVALID,
        )

    proposal = vec["proposal"]

    if not isinstance(proposal, dict):
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="vector file field 'proposal' must be an object",
            reason_code=DC_VECTOR_INVALID,
        )

    # Reject sig evidence in trust_sanitization mode. This mode does NOT
    # handle embedded_keyring (no sig vectors are in the regression matrix),
    # so a sig-evidence proposal would reach verify_proposal() with no
    # keyring plumbing and fall back to PIC_KEYS_PATH / default-keyring
    # resolution — re-opening the env-var fallback hole that evidence-mode
    # explicitly closes. Authors who need sig-evidence coverage should use
    # evidence mode (conformance/evidence/README.md).
    if _proposal_contains_sig_evidence(proposal):
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=(
                "trust_sanitization vectors must not contain sig evidence; "
                "use evidence mode for signature-evidence conformance"
            ),
            reason_code=DC_VECTOR_INVALID,
        )

    # Hermeticity guard for the financial_hash_ok matrix cells: if the
    # proposal carries file-backed hash evidence, evidence_root_dir must
    # be a non-empty string. Other matrix cells have no evidence and this
    # guard is a no-op.
    if _proposal_contains_file_hash_evidence(proposal):
        erd = options_dict.get("evidence_root_dir")
        if not isinstance(erd, str) or not erd:
            return VectorResult(
                id=vid,
                mode="trust_sanitization",
                passed=False,
                reason=(
                    "trust_sanitization vector with file-backed hash evidence must set "
                    "non-empty string options.evidence_root_dir"
                ),
                reason_code=DC_VECTOR_INVALID,
            )

    # Resolve evidence_root_dir against repo root (reuses the evidence-mode
    # helper; same invariants apply). No-op for vectors without
    # evidence_root_dir.
    try:
        options_dict = _resolve_evidence_root_against_repo_root(options_dict)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=f"could not resolve evidence_root_dir: {type(e).__name__}: {e}",
            reason_code=DC_VECTOR_INVALID,
        )

    # Derive proposal_base_dir from the resolved evidence_root_dir so
    # file://<name> refs resolve under the configured artifact root.
    if "evidence_root_dir" in options_dict:
        options_dict = {
            **options_dict,
            "proposal_base_dir": options_dict["evidence_root_dir"],
        }

    try:
        options = PipelineOptions(**options_dict)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=f"could not construct PipelineOptions: {type(e).__name__}: {e}",
            reason_code=DC_VECTOR_INVALID,
        )

    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=PICTrustFutureWarning)
            result = verify_proposal(proposal, options=options)
    except Exception as e:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=f"verify_proposal() raised {type(e).__name__}: {e}",
            reason_code=DC_RUNNER_ERROR,
        )

    if entry["expected"] == "allow":
        if result.ok:
            return VectorResult(id=vid, mode="trust_sanitization", passed=True)
        code = result.error.code.value if (result.error and result.error.code) else "<none>"
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=f"expected allow but got block ({code})",
            reason_code=DC_VERDICT_MISMATCH,
        )

    # expected == "block"
    if result.ok:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="expected block but proposal was allowed",
            reason_code=DC_VERDICT_MISMATCH,
        )
    if result.error is None or result.error.code is None:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason="expected block with error code, got block with no error code",
            reason_code=DC_ERROR_CODE_MISMATCH,
        )
    actual_code = result.error.code.value
    expected_code = entry["expected_error_code"]
    if actual_code != expected_code:
        return VectorResult(
            id=vid,
            mode="trust_sanitization",
            passed=False,
            reason=f"expected {expected_code} but got {actual_code}",
            reason_code=DC_ERROR_CODE_MISMATCH,
        )
    return VectorResult(id=vid, mode="trust_sanitization", passed=True)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def run_manifest(
    manifest_path: Path,
    *,
    filter_modes: Optional[List[str]] = None,
    filter_ids: Optional[List[str]] = None,
) -> RunnerReport:
    """Load and validate a manifest, execute every selected vector, return aggregate report.

    ``filter_modes`` / ``filter_ids`` are optional union filters per
    design checkpoint §1 (see :func:`_apply_filters`). When neither is
    set, all manifest vectors are selected. When set and the filter
    selects zero vectors, the returned report has
    ``diagnostic=DC_NO_VECTORS_SELECTED`` + a freeform message + an
    empty ``results`` list; :func:`main` then exits 2 per §5.

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
    all_entries = manifest["vectors"]
    selected_entries = _apply_filters(all_entries, filter_modes=filter_modes, filter_ids=filter_ids)
    selection = Selection(
        total_in_manifest=len(all_entries),
        selected=len(selected_entries),
        filter_modes=list(filter_modes or []),
        filter_ids=list(filter_ids or []),
    )
    report = RunnerReport(
        manifest_version=manifest["version"],
        selection=selection,
    )

    # Empty selection with non-empty filters → diagnostic + exit 2 per §4.
    # Empty manifest with no filters → vacuous success (all_passed=True,
    # exit_code=0) per §5; no diagnostic.
    if not selected_entries and (filter_modes or filter_ids):
        report.diagnostic = DC_NO_VECTORS_SELECTED
        report.message = (
            f"filter selected zero vectors "
            f"(filter_modes={list(filter_modes or [])}, "
            f"filter_ids={list(filter_ids or [])})"
        )
        return report

    for entry in selected_entries:
        vec_path = conformance_root / entry["file"]
        if not vec_path.exists():
            report.results.append(
                VectorResult(
                    id=entry["id"],
                    mode=entry["mode"],
                    passed=False,
                    reason=f"vector file not found: {entry['file']}",
                    reason_code=DC_MANIFEST_DRIFT,
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
                    reason_code=DC_VECTOR_INVALID,
                )
            )
            continue

        # Vector root type guard: a vector file containing `[]`, `"x"`, or
        # `123` would crash `vec.get("id")` below with AttributeError.
        # Fail-closed with a clear vector_invalid reason instead.
        if not isinstance(vec, dict):
            report.results.append(
                VectorResult(
                    id=entry["id"],
                    mode=entry["mode"],
                    passed=False,
                    reason="vector file root must be a JSON object",
                    reason_code=DC_VECTOR_INVALID,
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
                    reason_code=DC_MANIFEST_DRIFT,
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
                    reason_code=DC_MANIFEST_DRIFT,
                )
            )
            continue

        if entry["mode"] == "canonicalization":
            report.results.append(_run_canonicalization_vector(vec))
        elif entry["mode"] == "evidence":
            report.results.append(_run_evidence_vector(vec, entry))
        elif entry["mode"] == "trust_sanitization":
            report.results.append(_run_trust_sanitization_vector(vec, entry))
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
            "PIC Conformance Runner v0.1 — executes canonicalization, core, "
            "evidence, and trust_sanitization vectors."
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
        help="Show per-vector detail even for passing vectors (human mode only).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Emit machine-readable JSON output to stdout instead of human "
            "text. Suppresses all human prose; the manifest-error envelope "
            "goes to stdout (not stderr) so JSON consumers can parse a "
            "single stream."
        ),
    )
    parser.add_argument(
        "--filter-mode",
        action="append",
        default=None,
        metavar="MODE",
        help=(
            "Run only vectors whose mode matches MODE (one of: "
            "canonicalization, core, evidence, trust_sanitization). "
            "Repeatable; multiple flags union together. Unions with "
            "--filter-id. Unknown mode names select nothing and trigger "
            "exit 2 with summary.diagnostic='no_vectors_selected'."
        ),
    )
    parser.add_argument(
        "--filter-id",
        action="append",
        default=None,
        metavar="ID",
        help=(
            "Run only the vector with the exact ID. Repeatable; multiple "
            "flags union together. Unions with --filter-mode. Unknown IDs "
            "select nothing and trigger exit 2 with "
            "summary.diagnostic='no_vectors_selected'."
        ),
    )
    args = parser.parse_args(argv)

    renderer: Renderer = JsonRenderer() if args.json else HumanRenderer()

    try:
        report = run_manifest(
            Path(args.manifest),
            filter_modes=args.filter_mode,
            filter_ids=args.filter_id,
        )
    except ManifestError as e:
        # Human mode: print to stderr (byte-identical to v0.8.2 PR V8.2-2).
        # JSON mode:  print the manifest-error envelope to stdout per the
        # PR V8.2-3 design checkpoint §2 lock — JSON consumers MUST be
        # able to parse a single stream without merging stderr.
        rendered = renderer.render_manifest_error(str(e))
        if args.json:
            print(rendered)
        else:
            print(rendered, file=sys.stderr)
        return 2

    # Success path AND no_vectors_selected path both render the report.
    # In human mode, no_vectors_selected output goes to stdout per the
    # PR V8.2-3 design checkpoint approval: a report with a diagnostic
    # IS still a report. ManifestError is different — it short-circuits
    # before the report exists.
    print(renderer.render_report(report, verbose=args.verbose))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
