"""Case runner for the refund-sandbox PIC verifier adapter and fixture maker.

Run in the pinned environment:
    python run_cases.py [--expectations PATH] [--report PATH] [--case ID ...]

Exit codes:
  0  every selected case matched the expectations in the pinned environment
  1  at least one case mismatched, failed validation or raised
  2  unsafe report path, report cleanup or write failure, the adapter could
     not be loaded, or the expectations failed the coverage gate
     (malformed, empty, duplicate ids, ids differing from the cases
     registered here, or unknown or repeated --case ids)
  3  the installed pic-standard is not the declared pin, its installation
     could not be established, or the SDK-dependent helpers could not be
     loaded; no case runs

Reports: once the arguments parse and the report path passes its safety
checks, the previous report is deleted before anything else, and each
handled exit writes a new report with status not-run, passed or failed,
when report I/O succeeds. A report path that aliases the expectations, a
protected input directory, a non-JSON file or any file that is not a
report written by this runner is refused before anything is deleted. The
report records classifications and validation problems only, not
timestamps or paths.

These are component checks of this example: the adapter and the fixture
maker, including fixture signing with the public test key. They do not
exercise admission, handoff or resolution signing, execution or any
connected workflow.

Independence: the result contract (field set, schema), raw-file hashing,
the environment gate and the expectations parser are implemented here,
not borrowed from pic_result.py. The pinned SDK canonicalizer is used
deliberately for JCS bytes and the args/claims digests.

Isolation: each case runs in its own temporary directory with a fresh
output path. SDK spies, metadata fakes, key-directory redirects and
injected failures are patches restored after the case; the committed keys
and the installed environment are never modified.

The file is not named test_*.py, so the repository's root pytest run does
not collect it, and importing it only registers case functions.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

HERE = Path(__file__).resolve().parent
EXPECTED_PATH = HERE / "fixtures" / "expected-outcomes.json"
ACTUAL_PATH = HERE / "actual-results.json"
PROTECTED_DIRS = (HERE / "keys", HERE / "fixtures")
EXPECTATIONS_FORMAT = "refund-sandbox-pic-cases/1"
REPORT_FORMAT = "refund-sandbox-pic-case-report/1"
SUBPROCESS_TIMEOUT_SECONDS = 120

# The result contract, declared independently of pic_result.py.
RESULT_SCHEMA = "refund-sandbox-pic-result/0.1"
RESULT_FIELDS = frozenset(
    {
        "schema",
        "contract_revision",
        "run_id",
        "pic_sdk_commit",
        "proposal_file_ref",
        "pic_trust_file_ref",
        "evaluated_at",
        "result",
        "tool",
        "impact",
        "args_digest",
        "claims_digest",
        "intent_digest",
        "error_code",
    }
)
VERIFIED_FIELDS = ("tool", "impact", "args_digest", "claims_digest", "intent_digest")
RUN_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
EVALUATED_AT_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")

RUN_ID = "case-run"
DECISION_ID = "synthetic-decision-001"
SYNTHETIC_REF = "ab" * 32
OTHER_SEED = bytes(range(32))
PAST = "2026-01-01T00:00:00Z"
FAR_FUTURE = "2099-12-31T23:59:59Z"

CASE_ID_RE = re.compile(r"[a-z][0-9]{2}_[a-z0-9_]+")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
OUTPUTS = frozenset({"written", "absent", "unchanged"})
RESULTS = frozenset({"allow", "block"})
REF_CLASSES = frozenset({"bound", "null", "proposal-only"})
PIN_CLASSES = frozenset({"pin", "null"})
WRITTEN_KEYS = ("result", "error_code", "refs", "sdk_pin")
COMPARED_KEYS = (
    "exit_code",
    "output",
    "result",
    "error_code",
    "refs",
    "sdk_pin",
    "native_calls",
    "file_reads",
    "refs_differ",
    "fixture_exit_code",
)
ALLOWED_KEYS = frozenset({"id", "description", *COMPARED_KEYS})

M = SimpleNamespace()
E = SimpleNamespace(revision=None, pin=None)
CASES: Dict[str, SimpleNamespace] = {}


def case(
    case_id: str,
    *,
    kind: str = "adapter",
    preflight: bool = False,
    pair: bool = False,
    fixture_exit: bool = False,
) -> Callable[[Callable[[Path], Dict[str, Any]]], Callable[[Path], Dict[str, Any]]]:
    """Register a case. kind is adapter (in-process), subprocess or fixture."""

    def register(fn: Callable[[Path], Dict[str, Any]]) -> Callable[[Path], Dict[str, Any]]:
        if case_id in CASES:
            raise ValueError(f"duplicate case id {case_id}")
        CASES[case_id] = SimpleNamespace(
            fn=fn, kind=kind, preflight=preflight, pair=pair, fixture_exit=fixture_exit
        )
        return fn

    return register


# ----------------------------------------------------------------------------
# Runner-owned strict JSON and environment gate.
# ----------------------------------------------------------------------------


def _strict_object(pairs: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate member {key!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise ValueError(f"non-JSON constant {name}")


def strict_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_strict_object, parse_constant=_no_constant)


def installed_commit(pin: str) -> Tuple[bool, str]:
    """Independent check that pic-standard is a git install of exactly `pin`."""
    try:
        raw = importlib.metadata.distribution("pic-standard").read_text("direct_url.json")
    except importlib.metadata.PackageNotFoundError:
        return False, "pic-standard is not installed"
    if raw is None:
        return False, "no direct_url.json"
    try:
        vcs = strict_json(raw).get("vcs_info")
    except (ValueError, AttributeError):
        return False, "malformed direct_url.json"
    if not isinstance(vcs, dict) or vcs.get("vcs") != "git" or vcs.get("commit_id") != pin:
        return False, f"installed revision is not git commit {pin}"
    return True, ""


def _load_adapter() -> None:
    """pic_result.py imports only the standard library at module level."""
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    import pic_result

    M.pr = pic_result


def _load_sdk_helpers() -> None:
    """SDK-dependent helpers; called only after the environment gate."""
    import make_fixture
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from pic_standard import canonical, evidence, pipeline
    from pic_standard.errors import PICError, PICErrorCode

    M.mf = make_fixture
    M.canonical, M.evidence, M.pipeline = canonical, evidence, pipeline
    M.PICError, M.PICErrorCode = PICError, PICErrorCode
    M.other_key = ed25519.Ed25519PrivateKey.from_private_bytes(OTHER_SEED)
    M.public_hex = (HERE / "keys" / "merchant_test_public.hex").read_text("utf-8").strip()


# ----------------------------------------------------------------------------
# Patches and spies.
# ----------------------------------------------------------------------------


@contextlib.contextmanager
def patched(target: Any, name: str, value: Any) -> Iterator[None]:
    original = getattr(target, name)
    setattr(target, name, value)
    try:
        yield
    finally:
        setattr(target, name, original)


@contextlib.contextmanager
def spies() -> Iterator[Dict[str, int]]:
    """Count native verification calls and SDK evidence-file reads."""
    counts = {"native_calls": 0, "file_reads": 0}
    verify = M.pipeline.verify_proposal
    read = M.evidence._read_sandboxed_file

    def counting_verify(*args: Any, **kwargs: Any) -> Any:
        counts["native_calls"] += 1
        return verify(*args, **kwargs)

    def counting_read(*args: Any, **kwargs: Any) -> Any:
        counts["file_reads"] += 1
        return read(*args, **kwargs)

    with (
        patched(M.pipeline, "verify_proposal", counting_verify),
        patched(M.evidence, "_read_sandboxed_file", counting_read),
    ):
        yield counts


class FakeDistribution:
    def __init__(self, direct_url: Optional[str]) -> None:
        self.direct_url = direct_url

    def read_text(self, name: str) -> Optional[str]:
        return self.direct_url if name == "direct_url.json" else None


def fake_metadata(direct_url: Optional[str], *, installed: bool = True) -> Any:
    def distribution(name: str) -> FakeDistribution:
        if not installed:
            raise importlib.metadata.PackageNotFoundError(name)
        return FakeDistribution(direct_url)

    return patched(importlib.metadata, "distribution", distribution)


# ----------------------------------------------------------------------------
# Inputs.
# ----------------------------------------------------------------------------


def sha256_ref(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def dump(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("ascii")


def refund_args(**changes: Any) -> Dict[str, Any]:
    args: Dict[str, Any] = {"payment_id": "pay_A", "amount_minor": 4000, "currency": "EUR"}
    args.update(changes)
    return args


def signed(
    *,
    args: Optional[Dict[str, Any]] = None,
    decision_id: str = DECISION_ID,
    approval_ref: str = SYNTHETIC_REF,
    claim_text: Optional[str] = None,
    claims: Optional[List[Dict[str, Any]]] = None,
    tool: str = "refund",
    impact: str = "money",
    expires_at: Optional[str] = None,
    private_key: Any = None,
    key_id: Optional[str] = None,
    edit_attestation: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> Dict[str, Any]:
    """Signed proposal; every parameter is a deliberate variation for one case."""
    args = refund_args() if args is None else args
    intent = M.mf.fixture_intent(decision_id=decision_id, args=args, reference_source="synthetic")
    proposal = M.mf.build_proposal(
        decision_id=decision_id, approval_ref=approval_ref, args=args, intent=intent
    )
    proposal["action"]["tool"] = tool
    proposal["impact"] = impact
    if claim_text is not None:
        proposal["claims"][0]["text"] = claim_text
    if claims is not None:
        proposal["claims"] = claims
    attestation = M.mf.build_attestation(proposal, expires_at=expires_at or M.mf.expiry_after(1800))
    if edit_attestation is not None:
        edit_attestation(attestation)
    payload, signature = M.mf.sign_attestation(
        attestation, private_key or M.mf.load_test_private_key()
    )
    return M.mf.attach_sig_evidence(
        proposal, payload=payload, signature=signature, key_id=key_id or M.mf.KEY_ID
    )


def committed_keyring() -> bytes:
    return (HERE / "keys" / "pic_keys.example.json").read_bytes()


def keyring(trusted: Optional[Dict[str, Any]] = None, revoked: Optional[list] = None) -> bytes:
    return dump(
        {
            "trusted_keys": {M.mf.KEY_ID: M.public_hex} if trusted is None else trusted,
            "revoked_keys": [] if revoked is None else revoked,
        }
    )


def after_signing(edit: Callable[[Dict[str, Any]], Any]) -> bytes:
    proposal = signed()
    edit(proposal)
    return dump(proposal)


def with_payload(edit: Callable[[str], str]) -> bytes:
    proposal = signed()
    entry = proposal["evidence"][0]
    entry["payload"] = edit(entry["payload"])
    return dump(proposal)


# ----------------------------------------------------------------------------
# Output validation.
# ----------------------------------------------------------------------------


def expected_context(run_id: str, revision: str) -> Tuple[Optional[str], Optional[str]]:
    """Specified null behavior: an invalid run_id nulls both; a wrong revision nulls it."""
    if not RUN_ID_RE.fullmatch(run_id):
        return None, None
    return run_id, (revision if revision == E.revision else None)


def evaluated_at_ok(value: Any, started: datetime, finished: datetime) -> bool:
    """UTC milliseconds, rounded up from a completion instant inside the invocation."""
    if not isinstance(value, str) or not EVALUATED_AT_RE.fullmatch(value):
        return False
    try:
        instant = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return started <= instant <= finished + timedelta(milliseconds=1)


def inspect_output(
    out: Path,
    before: Optional[bytes],
    *,
    proposal: Optional[bytes],
    keyring_bytes: Optional[bytes],
    run_id: str,
    revision: str,
    exit_code: int,
    started: datetime,
    finished: datetime,
) -> Dict[str, Any]:
    if not out.exists():
        return {"output": "absent", "problems": []}
    data = out.read_bytes()
    if before is not None:
        return {"output": "unchanged" if data == before else "replaced", "problems": []}
    problems: List[str] = []
    try:
        result = strict_json(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"output": "written", "problems": ["output-not-strict-json"]}
    if not isinstance(result, dict) or set(result) != RESULT_FIELDS:
        return {"output": "written", "problems": ["field-set"]}
    if data != M.canonical.canonicalize(result):
        problems.append("bytes-not-jcs")
    if result["schema"] != RESULT_SCHEMA:
        problems.append("schema")
    if not evaluated_at_ok(result["evaluated_at"], started, finished):
        problems.append("evaluated-at")

    want_run_id, want_revision = expected_context(run_id, revision)
    if result["run_id"] != want_run_id:
        problems.append("metadata-run-id")
    if result["contract_revision"] != want_revision:
        problems.append("metadata-revision")

    pin = result["pic_sdk_commit"]
    sdk_pin = "pin" if pin == E.pin else "null" if pin is None else "wrong"
    if sdk_pin == "wrong":
        problems.append("sdk-pin-wrong")

    want_p = sha256_ref(proposal) if proposal is not None else None
    want_k = sha256_ref(keyring_bytes) if keyring_bytes is not None else None
    got_p, got_k = result["proposal_file_ref"], result["pic_trust_file_ref"]
    if got_p is None and got_k is None:
        refs = "null"
    elif got_p == want_p and got_k == want_k:
        refs = "bound"
    elif got_p == want_p and got_k is None:
        refs = "proposal-only"
    else:
        refs = "wrong"
        problems.append("file-refs-wrong")

    verdict = result["result"]
    if verdict not in RESULTS:
        problems.append("result-value")
    elif verdict == "allow":
        if exit_code != 0:
            problems.append("allow-with-nonzero-exit")
        if result["error_code"] is not None:
            problems.append("allow-with-error-code")
        if sdk_pin != "pin" or refs != "bound":
            problems.append("allow-without-pin-or-bindings")
        parsed = json.loads(proposal or b"null")
        expected = {
            "tool": "refund",
            "impact": "money",
            "args_digest": hashlib.sha256(
                M.canonical.canonicalize(parsed["action"]["args"])
            ).hexdigest(),
            "claims_digest": hashlib.sha256(M.canonical.canonicalize(parsed["claims"])).hexdigest(),
            "intent_digest": hashlib.sha256(parsed["intent"].encode("utf-8")).hexdigest(),
        }
        problems.extend(f"allow-{k}" for k, v in expected.items() if result[k] != v)
    else:
        if exit_code == 0:
            problems.append("block-with-zero-exit")
        if not (isinstance(result["error_code"], str) and result["error_code"]):
            problems.append("block-without-error-code")
        if any(result[k] is not None for k in VERIFIED_FIELDS):
            problems.append("block-carries-verified-fields")
    return {
        "output": "written",
        "result": verdict,
        "error_code": result["error_code"],
        "refs": refs,
        "sdk_pin": sdk_pin,
        "proposal_file_ref": got_p,
        "pic_trust_file_ref": got_k,
        "problems": problems,
    }


# ----------------------------------------------------------------------------
# Invocation.
# ----------------------------------------------------------------------------


def _write_inputs(tmp: Path, proposal: Optional[bytes], keyring_bytes: Optional[bytes]) -> None:
    tmp.mkdir(parents=True, exist_ok=True)
    if proposal is not None:
        (tmp / "proposal.json").write_bytes(proposal)
    if keyring_bytes is not None:
        (tmp / "keyring.json").write_bytes(keyring_bytes)


def _adapter_argv(tmp: Path, run_id: str, revision: str, out: Path) -> List[str]:
    return [
        "--proposal", str(tmp / "proposal.json"),
        "--keyring", str(tmp / "keyring.json"),
        "--run-id", run_id,
        "--contract-revision", revision,
        "--out", str(out),
    ]  # fmt: skip


def invoke(
    tmp: Path,
    proposal: Optional[bytes],
    keyring_bytes: Optional[bytes],
    *,
    run_id: str = RUN_ID,
    revision: Optional[str] = None,
    out: Optional[Path] = None,
    patches: tuple = (),
) -> Dict[str, Any]:
    """Run pic_result.main in-process with spies; a fresh output path unless given."""
    revision = revision or E.revision
    _write_inputs(tmp, proposal, keyring_bytes)
    out = out or tmp / "result.json"
    before = out.read_bytes() if out.exists() else None
    stderr = io.StringIO()
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        counts = stack.enter_context(spies())
        started = datetime.now(timezone.utc)
        with contextlib.redirect_stderr(stderr):
            exit_code = M.pr.main(_adapter_argv(tmp, run_id, revision, out))
        finished = datetime.now(timezone.utc)
    actual: Dict[str, Any] = {"exit_code": exit_code, **counts, "stderr": stderr.getvalue()}
    actual.update(
        inspect_output(
            out,
            before,
            proposal=proposal,
            keyring_bytes=keyring_bytes,
            run_id=run_id,
            revision=revision,
            exit_code=exit_code,
            started=started,
            finished=finished,
        )
    )
    return actual


def second_run_problems(second: Dict[str, Any]) -> List[str]:
    """The second invocation of a pair must itself be a complete, valid allow."""
    want = {
        "exit_code": 0,
        "output": "written",
        "result": "allow",
        "refs": "bound",
        "sdk_pin": "pin",
        "native_calls": 1,
        "file_reads": 0,
    }
    problems = [f"second-run-{k}" for k, v in want.items() if second.get(k) != v]
    return problems + [f"second-run-{p}" for p in second.get("problems", [])]


def run_fixture_maker(tmp: Path, extra: List[str], *, patches: tuple = ()) -> Dict[str, Any]:
    out = tmp / "fixture.json"
    before = out.read_bytes() if out.exists() else None
    argv = [
        "--decision-id", DECISION_ID,
        "--approval-ref", SYNTHETIC_REF,
        "--approval-ref-source", "synthetic",
        "--payment-id", "pay_A",
        "--amount-minor", "4000",
        "--currency", "EUR",
        "--out", str(out),
        *extra,
    ]  # fmt: skip
    stderr = io.StringIO()
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        with contextlib.redirect_stderr(stderr):
            exit_code = M.mf.main(argv)
    if not out.exists():
        output = "absent"
    elif before is not None:
        output = "unchanged" if out.read_bytes() == before else "replaced"
    else:
        output = "written"
    return {"exit_code": exit_code, "output": output, "stderr": stderr.getvalue(), "problems": []}


def _raise_runtime(*args: Any, **kwargs: Any) -> Any:
    raise RuntimeError("injected SDK failure")


def _raise_key_error(*args: Any, **kwargs: Any) -> Any:
    raise KeyError("injected adapter failure")


def _native_internal_error(*args: Any, **kwargs: Any) -> Any:
    error = M.PICError(code=M.PICErrorCode.INTERNAL_ERROR, message="injected")
    return M.pipeline.PipelineResult(ok=False, error=error)


# ----------------------------------------------------------------------------
# Cases.
# ----------------------------------------------------------------------------


@case("a01_valid_allow")
def _a01(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), committed_keyring())


@case("a02_valid_cli_subprocess", kind="subprocess")
def _a02(tmp: Path) -> Dict[str, Any]:
    proposal, keyring_bytes = dump(signed()), committed_keyring()
    _write_inputs(tmp, proposal, keyring_bytes)
    out = tmp / "result.json"
    command = [
        sys.executable,
        str(HERE / "pic_result.py"),
        *_adapter_argv(tmp, RUN_ID, E.revision, out),
    ]
    started = datetime.now(timezone.utc)
    try:
        done = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=SUBPROCESS_TIMEOUT_SECONDS,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        return {"exception": f"subprocess timed out after {SUBPROCESS_TIMEOUT_SECONDS}s"}
    finished = datetime.now(timezone.utc)
    actual: Dict[str, Any] = {"exit_code": done.returncode, "stderr": done.stderr}
    actual.update(
        inspect_output(
            out,
            None,
            proposal=proposal,
            keyring_bytes=keyring_bytes,
            run_id=RUN_ID,
            revision=E.revision,
            exit_code=done.returncode,
            started=started,
            finished=finished,
        )
    )
    return actual


@case("a03_valid_structured_key_unexpired")
def _a03(tmp: Path) -> Dict[str, Any]:
    entry = {"public_key": M.public_hex, "expires_at": FAR_FUTURE}
    return invoke(tmp, dump(signed()), keyring({M.mf.KEY_ID: entry}))


@case("b01_args_payment_changed")
def _b01(tmp: Path) -> Dict[str, Any]:
    edit = lambda p: p["action"]["args"].update(payment_id="pay_B")  # noqa: E731
    return invoke(tmp, after_signing(edit), committed_keyring())


@case("b02_args_amount_changed")
def _b02(tmp: Path) -> Dict[str, Any]:
    edit = lambda p: p["action"]["args"].update(amount_minor=3999)  # noqa: E731
    return invoke(tmp, after_signing(edit), committed_keyring())


@case("b03_args_currency_changed")
def _b03(tmp: Path) -> Dict[str, Any]:
    edit = lambda p: p["action"]["args"].update(currency="USD")  # noqa: E731
    return invoke(tmp, after_signing(edit), committed_keyring())


@case("b04_signed_for_other_tool")
def _b04(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(tool="transfer")), committed_keyring())


@case("b05_signed_for_other_impact")
def _b05(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(impact="privacy")), committed_keyring())


@case("c01_claim_changed_after_signing")
def _c01(tmp: Path) -> Dict[str, Any]:
    text = M.mf.canonical_claim_text(decision_id="other-decision", approval_ref=SYNTHETIC_REF)
    edit = lambda p: p["claims"][0].update(text=text)  # noqa: E731
    return invoke(tmp, after_signing(edit), committed_keyring())


@case("c02_intent_changed_after_signing")
def _c02(tmp: Path) -> Dict[str, Any]:
    edit = lambda p: p.update(intent="Refund something else.")  # noqa: E731
    return invoke(tmp, after_signing(edit), committed_keyring())


@case("c03_provenance_changed_after_signing")
def _c03(tmp: Path) -> Dict[str, Any]:
    edit = lambda p: p["provenance"][0].update(id="other-provenance")  # noqa: E731
    return invoke(tmp, after_signing(edit), committed_keyring())


@case("c04_claim_text_not_canonical")
def _c04(tmp: Path) -> Dict[str, Any]:
    text = json.dumps({"decision_id": DECISION_ID, "approval_ref": SYNTHETIC_REF})
    return invoke(tmp, dump(signed(claim_text=text)), committed_keyring())


@case("c05_claim_extra_member")
def _c05(tmp: Path) -> Dict[str, Any]:
    inner = {"approval_ref": SYNTHETIC_REF, "decision_id": DECISION_ID, "note": "extra"}
    text = M.canonical.canonicalize(inner).decode("utf-8")
    return invoke(tmp, dump(signed(claim_text=text)), committed_keyring())


@case("c06_approval_ref_not_hex")
def _c06(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(approval_ref="approval-001")), committed_keyring())


@case("c07_approval_ref_trailing_newline")
def _c07(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(approval_ref=SYNTHETIC_REF + "\n")), committed_keyring())


@case("c08_approval_ref_uppercase")
def _c08(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(approval_ref=SYNTHETIC_REF.upper())), committed_keyring())


@case("c09_decision_id_untrimmed")
def _c09(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(decision_id=f" {DECISION_ID}")), committed_keyring())


@case("c10_two_claims")
def _c10(tmp: Path) -> Dict[str, Any]:
    claim = {
        "text": M.mf.canonical_claim_text(decision_id=DECISION_ID, approval_ref=SYNTHETIC_REF),
        "evidence": [M.mf.PROVENANCE_ID],
    }
    return invoke(tmp, dump(signed(claims=[claim, dict(claim)])), committed_keyring())


@case("c11_claim_text_duplicate_member")
def _c11(tmp: Path) -> Dict[str, Any]:
    text = (
        f'{{"approval_ref":"{SYNTHETIC_REF}","approval_ref":"{SYNTHETIC_REF}","decision_id":"x"}}'
    )
    return invoke(tmp, dump(signed(claim_text=text)), committed_keyring())


@case("c12_claim_text_float")
def _c12(tmp: Path) -> Dict[str, Any]:
    text = f'{{"approval_ref":"{SYNTHETIC_REF}","decision_id":1.5}}'
    return invoke(tmp, dump(signed(claim_text=text)), committed_keyring())


@case("d01_missing_evidence", preflight=True)
def _d01(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, after_signing(lambda p: p.pop("evidence")), committed_keyring())


@case("d02_forged_signature")
def _d02(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(private_key=M.other_key)), committed_keyring())


@case("d03_expired_attestation")
def _d03(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(expires_at=PAST)), committed_keyring())


@case("d04_unknown_key_id")
def _d04(tmp: Path) -> Dict[str, Any]:
    proposal = signed(private_key=M.other_key, key_id="refund-sandbox-unknown-key")
    return invoke(tmp, dump(proposal), committed_keyring())


@case("d05_revoked_key")
def _d05(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), keyring(revoked=[M.mf.KEY_ID]))


@case("d06_expired_key")
def _d06(tmp: Path) -> Dict[str, Any]:
    entry = {"public_key": M.public_hex, "expires_at": PAST}
    return invoke(tmp, dump(signed()), keyring({M.mf.KEY_ID: entry}))


@case("d07_other_example_keyring")
def _d07(tmp: Path) -> Dict[str, Any]:
    other = (HERE.parent / "refund-approval" / "keys" / "pic_keys.example.json").read_bytes()
    return invoke(tmp, dump(signed()), other)


@case("e01_hash_evidence_only", preflight=True)
def _e01(tmp: Path) -> Dict[str, Any]:
    entry = {"id": "merchant-approval", "type": "hash", "ref": "file://evidence.bin",
             "sha256": "00" * 32}  # fmt: skip
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "evidence.bin").write_bytes(b"evidence")
    return invoke(tmp, after_signing(lambda p: p.update(evidence=[entry])), committed_keyring())


@case("e02_second_evidence_entry", preflight=True)
def _e02(tmp: Path) -> Dict[str, Any]:
    entry = {"id": "extra", "type": "hash", "ref": "file://evidence.bin", "sha256": "00" * 32}
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "evidence.bin").write_bytes(b"evidence")
    return invoke(tmp, after_signing(lambda p: p["evidence"].append(entry)), committed_keyring())


@case("e03_legacy_payload", preflight=True)
def _e03(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, with_payload(lambda _: "refund approved"), committed_keyring())


@case("e04_attestation_missing_expiry", preflight=True)
def _e04(tmp: Path) -> Dict[str, Any]:
    proposal = signed(edit_attestation=lambda a: a.pop("expires_at"))
    return invoke(tmp, dump(proposal), committed_keyring())


@case("e05_attestation_missing_intent_digest", preflight=True)
def _e05(tmp: Path) -> Dict[str, Any]:
    proposal = signed(edit_attestation=lambda a: a.pop("intent_digest"))
    return invoke(tmp, dump(proposal), committed_keyring())


@case("e06_attestation_extra_member", preflight=True)
def _e06(tmp: Path) -> Dict[str, Any]:
    proposal = signed(edit_attestation=lambda a: a.update(note="extra"))
    return invoke(tmp, dump(proposal), committed_keyring())


@case("e07_payload_duplicate_member", preflight=True)
def _e07(tmp: Path) -> Dict[str, Any]:
    edit = lambda s: s.replace("{", '{"tool":"refund",', 1)  # noqa: E731
    return invoke(tmp, with_payload(edit), committed_keyring())


@case("e08_payload_nan", preflight=True)
def _e08(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, with_payload(lambda s: s[:-1] + ',"n":NaN}'), committed_keyring())


@case("e09_payload_float", preflight=True)
def _e09(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, with_payload(lambda s: s[:-1] + ',"n":1.5}'), committed_keyring())


@case("f01_amount_boolean")
def _f01(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(args=refund_args(amount_minor=True))), committed_keyring())


@case("f02_amount_zero")
def _f02(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(args=refund_args(amount_minor=0))), committed_keyring())


@case("f03_amount_unsafe_integer")
def _f03(tmp: Path) -> Dict[str, Any]:
    raw = dump(signed()).replace(b'"amount_minor": 4000', b'"amount_minor": 9007199254740993')
    return invoke(tmp, raw, committed_keyring())


@case("f04_currency_usd")
def _f04(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(args=refund_args(currency="USD"))), committed_keyring())


@case("f05_extra_argument")
def _f05(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(args=refund_args(note="extra"))), committed_keyring())


@case("f06_payment_id_invalid")
def _f06(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed(args=refund_args(payment_id="pay A"))), committed_keyring())


@case("g01_duplicate_member")
def _g01(tmp: Path) -> Dict[str, Any]:
    raw = dump(signed()).replace(b"{\n", b'{\n  "impact": "money",\n', 1)
    return invoke(tmp, raw, committed_keyring())


@case("g02_nan")
def _g02(tmp: Path) -> Dict[str, Any]:
    raw = dump(signed()).replace(b'"amount_minor": 4000', b'"amount_minor": NaN')
    return invoke(tmp, raw, committed_keyring())


@case("g03_float")
def _g03(tmp: Path) -> Dict[str, Any]:
    raw = dump(signed()).replace(b'"amount_minor": 4000', b'"amount_minor": 4000.0')
    return invoke(tmp, raw, committed_keyring())


@case("g04_not_json")
def _g04(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, b"not json\n", committed_keyring())


@case("g05_not_object")
def _g05(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, b"[]\n", committed_keyring())


@case("g06_invalid_utf8")
def _g06(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, b"\xff\xfe{}", committed_keyring())


@case("h01_legacy_flat_shape")
def _h01(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), dump({M.mf.KEY_ID: M.public_hex}))


@case("h02_extra_member")
def _h02(tmp: Path) -> Dict[str, Any]:
    ring = {"trusted_keys": {M.mf.KEY_ID: M.public_hex}, "revoked_keys": [], "note": "x"}
    return invoke(tmp, dump(signed()), dump(ring))


@case("h03_uppercase_hex")
def _h03(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), keyring({M.mf.KEY_ID: M.public_hex.upper()}))


@case("h04_key_id_whitespace")
def _h04(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), keyring({f" {M.mf.KEY_ID}": M.public_hex}))


@case("h05_revoked_duplicate")
def _h05(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), keyring(revoked=["old-key", "old-key"]))


@case("h06_naive_key_expiry")
def _h06(tmp: Path) -> Dict[str, Any]:
    entry = {"public_key": M.public_hex, "expires_at": "2099-12-31T23:59:59"}
    return invoke(tmp, dump(signed()), keyring({M.mf.KEY_ID: entry}))


@case("h07_not_json")
def _h07(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), b"not json\n")


@case("i01_proposal_bytes_change_ref", pair=True)
def _i01(tmp: Path) -> Dict[str, Any]:
    proposal = signed()
    compact = json.dumps(proposal, sort_keys=True, separators=(",", ":")).encode("ascii")
    first = invoke(tmp / "pretty", dump(proposal), committed_keyring())
    second = invoke(tmp / "compact", compact, committed_keyring())
    first["refs_differ"] = (
        first.get("proposal_file_ref") is not None
        and second.get("proposal_file_ref") is not None
        and first["proposal_file_ref"] != second["proposal_file_ref"]
    )
    first["problems"] = first.get("problems", []) + second_run_problems(second)
    return first


@case("i02_keyring_bytes_change_ref", pair=True)
def _i02(tmp: Path) -> Dict[str, Any]:
    proposal = dump(signed())
    compact = json.dumps(strict_json(committed_keyring().decode("utf-8")), separators=(",", ":"))
    first = invoke(tmp / "pretty", proposal, committed_keyring())
    second = invoke(tmp / "compact", proposal, compact.encode("ascii"))
    first["refs_differ"] = (
        first.get("pic_trust_file_ref") is not None
        and second.get("pic_trust_file_ref") is not None
        and first["pic_trust_file_ref"] != second["pic_trust_file_ref"]
    )
    first["problems"] = first.get("problems", []) + second_run_problems(second)
    return first


def _env_case(tmp: Path, patch: Any) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), committed_keyring(), patches=(patch,))


@case("j01_no_direct_url")
def _j01(tmp: Path) -> Dict[str, Any]:
    return _env_case(tmp, fake_metadata(None))


@case("j02_local_directory_install")
def _j02(tmp: Path) -> Dict[str, Any]:
    return _env_case(tmp, fake_metadata('{"url": "file:///src", "dir_info": {}}'))


@case("j03_other_commit")
def _j03(tmp: Path) -> Dict[str, Any]:
    direct_url = json.dumps({"url": "x", "vcs_info": {"vcs": "git", "commit_id": "0" * 40}})
    return _env_case(tmp, fake_metadata(direct_url))


@case("j04_malformed_direct_url")
def _j04(tmp: Path) -> Dict[str, Any]:
    return _env_case(tmp, fake_metadata("{"))


@case("j05_not_installed")
def _j05(tmp: Path) -> Dict[str, Any]:
    return _env_case(tmp, fake_metadata(None, installed=False))


@case("k01_sdk_exception")
def _k01(tmp: Path) -> Dict[str, Any]:
    patch = patched(M.pipeline, "verify_proposal", _raise_runtime)
    return invoke(tmp, dump(signed()), committed_keyring(), patches=(patch,))


@case("k02_native_internal_error")
def _k02(tmp: Path) -> Dict[str, Any]:
    patch = patched(M.pipeline, "verify_proposal", _native_internal_error)
    return invoke(tmp, dump(signed()), committed_keyring(), patches=(patch,))


@case("k03_adapter_exception")
def _k03(tmp: Path) -> Dict[str, Any]:
    patch = patched(M.pr, "check_profile", _raise_key_error)
    return invoke(tmp, dump(signed()), committed_keyring(), patches=(patch,))


@case("k04_unknown_revision")
def _k04(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), committed_keyring(), revision="review-2026-10-19")


@case("k05_invalid_run_id")
def _k05(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, dump(signed()), committed_keyring(), run_id="bad run id!")


@case("k06_stale_output_refused")
def _k06(tmp: Path) -> Dict[str, Any]:
    tmp.mkdir(parents=True, exist_ok=True)
    out = tmp / "result.json"
    out.write_bytes(b'{"result":"allow"}')
    return invoke(tmp, dump(signed()), committed_keyring(), out=out)


@case("k07_unwritable_output")
def _k07(tmp: Path) -> Dict[str, Any]:
    out = tmp / "missing-directory" / "result.json"
    return invoke(tmp, dump(signed()), committed_keyring(), out=out)


@case("k08_missing_proposal_file")
def _k08(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, None, committed_keyring())


@case("k09_oversize_proposal")
def _k09(tmp: Path) -> Dict[str, Any]:
    return invoke(tmp, b" " * (M.pr.MAX_INPUT_BYTES + 1), committed_keyring())


@case("m01_bad_calendar_day", kind="fixture")
def _m01(tmp: Path) -> Dict[str, Any]:
    return run_fixture_maker(tmp, ["--expires-at", "2026-02-30T12:00:00Z"])


@case("m02_bad_calendar_month", kind="fixture")
def _m02(tmp: Path) -> Dict[str, Any]:
    return run_fixture_maker(tmp, ["--expires-at", "2026-13-01T12:00:00Z"])


@case("m03_ttl_overflow", kind="fixture")
def _m03(tmp: Path) -> Dict[str, Any]:
    return run_fixture_maker(tmp, ["--ttl-seconds", "99999999999999"])


@case("m04_missing_seed", kind="fixture")
def _m04(tmp: Path) -> Dict[str, Any]:
    return run_fixture_maker(tmp, [], patches=(patched(M.mf, "KEYS_DIR", tmp / "no-keys"),))


@case("m05_malformed_seed", kind="fixture")
def _m05(tmp: Path) -> Dict[str, Any]:
    keys = tmp / "bad-keys"
    keys.mkdir()
    (keys / "merchant_test_private.hex").write_text("zz-not-hex\n", encoding="utf-8")
    return run_fixture_maker(tmp, [], patches=(patched(M.mf, "KEYS_DIR", keys),))


@case("m06_existing_output_refused", kind="fixture")
def _m06(tmp: Path) -> Dict[str, Any]:
    (tmp / "fixture.json").write_bytes(b"{}\n")
    return run_fixture_maker(tmp, [])


@case("m07_invalid_approval_ref", kind="fixture")
def _m07(tmp: Path) -> Dict[str, Any]:
    return run_fixture_maker(tmp, ["--approval-ref", "approval-001"])


@case("m08_past_expiry_then_block", fixture_exit=True)
def _m08(tmp: Path) -> Dict[str, Any]:
    made = run_fixture_maker(tmp, ["--expires-at", PAST])
    fixture = tmp / "fixture.json"
    proposal = fixture.read_bytes() if fixture.exists() else None
    actual = invoke(tmp / "verify", proposal, committed_keyring())
    actual["fixture_exit_code"] = made["exit_code"]
    return actual


# ----------------------------------------------------------------------------
# Expectations gate.
# ----------------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def entry_problems(entry: Any) -> Tuple[Optional[str], List[str]]:
    """Type-check one expectation entry before any of its values are used."""
    if not isinstance(entry, dict):
        return None, [f"entry must be an object: {entry!r}"]
    case_id = entry.get("id")
    if not (isinstance(case_id, str) and CASE_ID_RE.fullmatch(case_id)):
        return None, [f"invalid id {case_id!r}"]
    problems: List[str] = []

    def bad(message: str) -> None:
        problems.append(f"{case_id}: {message}")

    unknown = sorted(k for k in entry if k not in ALLOWED_KEYS)
    if unknown:
        bad(f"unknown keys {unknown}")
    if not _is_text(entry.get("description")):
        bad("description must be a nonempty string")
    if not (_is_int(entry.get("exit_code")) and entry["exit_code"] in (0, 1, 2)):
        bad("exit_code must be the integer 0, 1 or 2")
    output = entry.get("output")
    if not (isinstance(output, str) and output in OUTPUTS):
        bad(f"output must be one of {sorted(OUTPUTS)}")
    spec = CASES.get(case_id)
    if spec is None:
        bad("no registered case with this id")
        return case_id, problems

    result_written = spec.kind in ("adapter", "subprocess") and output == "written"
    for key in WRITTEN_KEYS:
        if result_written and key not in entry:
            bad(f"written result requires {key}")
        if not result_written and key in entry:
            bad(f"{key} does not apply without a written result")
    if "result" in entry and not (isinstance(entry["result"], str) and entry["result"] in RESULTS):
        bad(f"result must be one of {sorted(RESULTS)}")
    if "error_code" in entry and not (entry["error_code"] is None or _is_text(entry["error_code"])):
        bad("error_code must be a nonempty string or null")
    if "refs" in entry and not (isinstance(entry["refs"], str) and entry["refs"] in REF_CLASSES):
        bad(f"refs must be one of {sorted(REF_CLASSES)}")
    if "sdk_pin" in entry and not (
        isinstance(entry["sdk_pin"], str) and entry["sdk_pin"] in PIN_CLASSES
    ):
        bad(f"sdk_pin must be one of {sorted(PIN_CLASSES)}")

    for key in ("native_calls", "file_reads"):
        if spec.kind != "adapter":
            if key in entry:
                bad(f"{key} cannot be observed for a {spec.kind} case")
            continue
        if not (_is_int(entry.get(key)) and entry[key] >= 0):
            bad(f"{key} is required as a non-negative integer")
    if spec.kind == "adapter" and entry.get("file_reads") != 0:
        bad("file_reads must be 0 for every in-process adapter case")
    if spec.preflight and entry.get("native_calls") != 0:
        bad("preflight cases must expect native_calls 0")

    if spec.pair != ("refs_differ" in entry):
        bad("refs_differ is required for, and only for, paired binding cases")
    if "refs_differ" in entry and not isinstance(entry["refs_differ"], bool):
        bad("refs_differ must be a boolean")
    if spec.fixture_exit != ("fixture_exit_code" in entry):
        bad("fixture_exit_code is required for, and only for, fixture-then-verify cases")
    if "fixture_exit_code" in entry and not _is_int(entry["fixture_exit_code"]):
        bad("fixture_exit_code must be an integer")
    return case_id, problems


def coverage_problems(expectations: Any) -> List[str]:
    try:
        if not isinstance(expectations, dict):
            return ["expectations must be an object"]
        problems: List[str] = []
        if expectations.get("format") != EXPECTATIONS_FORMAT:
            problems.append(f"format must be {EXPECTATIONS_FORMAT!r}")
        if not _is_text(expectations.get("contract_revision")):
            problems.append("contract_revision must be a nonempty string")
        pin = expectations.get("pic_commit")
        if not (isinstance(pin, str) and COMMIT_RE.fullmatch(pin)):
            problems.append("pic_commit must be a 40-character lowercase hex commit")
        cases = expectations.get("cases")
        if not isinstance(cases, list) or not cases:
            return [*problems, "cases must be a nonempty list"]
        ids: List[str] = []
        for entry in cases:
            case_id, entry_issues = entry_problems(entry)
            problems.extend(entry_issues)
            if case_id is not None:
                ids.append(case_id)
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            problems.append(f"duplicate ids: {duplicates}")
        missing = sorted(set(CASES) - set(ids))
        if missing:
            problems.append(f"registered cases without expectations: {missing}")
        return problems
    except Exception as e:
        return [f"coverage gate failed: {type(e).__name__}: {e}"]


# ----------------------------------------------------------------------------
# Reports.
# ----------------------------------------------------------------------------


def report_path_problem(report: Path, expectations: Path) -> Optional[str]:
    """Refuse report paths that could delete or overwrite anything but a runner report."""
    try:
        if report.is_symlink():
            return "report path is a symlink"
        target = report.resolve()
        if target.suffix != ".json":
            return "report path must end in .json"
        if target == expectations.resolve():
            return "report path is the expectations file"
        for protected in PROTECTED_DIRS:
            if target.is_relative_to(protected.resolve()):
                return f"report path is inside protected directory {protected.name}/"
        if os.path.lexists(target):
            if not target.is_file():
                return "existing report path is not a regular file"
            try:
                existing = strict_json(target.read_text("utf-8"))
            except (UnicodeDecodeError, ValueError):
                return "existing file at report path is not a report written by this runner"
            if not (isinstance(existing, dict) and existing.get("report_format") == REPORT_FORMAT):
                return "existing file at report path is not a report written by this runner"
    except OSError as e:
        return f"cannot inspect report path: {e}"
    return None


def write_report(path: Path, status: str, **fields: Any) -> None:
    """Atomic write of a runner report; raises OSError on failure."""
    report = {
        "report_format": REPORT_FORMAT,
        "status": status,
        "scope": "component checks of this example only; no connected workflow",
        **fields,
    }
    data = (json.dumps(report, indent=2) + "\n").encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=".case-report-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ----------------------------------------------------------------------------
# Runner.
# ----------------------------------------------------------------------------


def run_case(case_id: str) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="refund-sandbox-case-") as tmp:
        try:
            return CASES[case_id].fn(Path(tmp))
        except Exception as e:
            return {"exception": f"{type(e).__name__}: {e}"}


def compare(expected: Dict[str, Any], actual: Dict[str, Any]) -> List[str]:
    diffs: List[str] = []
    if "exception" in actual:
        diffs.append(f"case raised {actual['exception']}")
    for key in COMPARED_KEYS:
        if key not in expected:
            continue
        got = actual.get(key, "<missing>")
        if type(got) is not type(expected[key]) or got != expected[key]:
            diffs.append(f"{key}: expected {expected[key]!r}, got {got!r}")
    if actual.get("problems"):
        diffs.append(f"validation problems: {actual['problems']}")
    return diffs


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--expectations", type=Path, default=EXPECTED_PATH)
    parser.add_argument("--report", type=Path, default=ACTUAL_PATH)
    parser.add_argument("--case", action="append", dest="cases", default=None)
    args = parser.parse_args(argv)

    problem = report_path_problem(args.report, args.expectations)
    if problem:
        print(f"run_cases: refusing report path {args.report}: {problem}", file=sys.stderr)
        return 2
    try:
        with contextlib.suppress(FileNotFoundError):
            args.report.unlink()
    except OSError as e:
        print(f"run_cases: cannot remove previous report {args.report}: {e}", file=sys.stderr)
        return 2

    def finish(code: int, status: str, **fields: Any) -> int:
        try:
            write_report(args.report, status, exit_code=code, **fields)
        except OSError as e:
            print(f"run_cases: cannot write report {args.report}: {e}", file=sys.stderr)
            return 2
        return code

    def not_run(code: int, reasons: List[str]) -> int:
        for reason in reasons:
            print(f"run_cases: {reason}", file=sys.stderr)
        return finish(code, "not-run", reasons=reasons, results=[])

    try:
        _load_adapter()
    except Exception as e:
        return not_run(2, [f"cannot load pic_result.py: {type(e).__name__}: {e}"])
    try:
        expectations = strict_json(args.expectations.read_text("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return not_run(2, [f"cannot read expectations: {e}"])

    problems = coverage_problems(expectations)
    if problems:
        return not_run(2, [f"coverage: {p}" for p in problems])

    all_ids = [entry["id"] for entry in expectations["cases"]]
    selected = args.cases if args.cases is not None else all_ids
    unknown = sorted(set(selected) - set(all_ids))
    repeated = sorted({i for i in selected if selected.count(i) > 1})
    if unknown or repeated:
        reasons = []
        if unknown:
            reasons.append(f"coverage: unknown --case ids: {unknown}")
        if repeated:
            reasons.append(f"coverage: repeated --case ids: {repeated}")
        return not_run(2, reasons)

    E.revision, E.pin = expectations["contract_revision"], expectations["pic_commit"]
    try:
        ok, reason = installed_commit(E.pin)
    except Exception as e:
        ok, reason = False, f"cannot establish the installation: {type(e).__name__}: {e}"
    if not ok:
        return not_run(3, [f"environment unverified: {reason}"])
    try:
        _load_sdk_helpers()
    except Exception as e:
        return not_run(3, [f"cannot load SDK-dependent helpers: {type(e).__name__}: {e}"])

    by_id = {entry["id"]: entry for entry in expectations["cases"]}
    results = []
    for case_id in selected:
        actual = run_case(case_id)
        diffs = compare(by_id[case_id], actual)
        print(f"{'PASS' if not diffs else 'FAIL'} {case_id}")
        for diff in diffs:
            print(f"     {diff}")
        if diffs and actual.get("stderr"):
            print(f"     stderr: {actual['stderr'].strip()}")
        recorded = {k: actual[k] for k in COMPARED_KEYS if k in actual}
        recorded["problems"] = actual.get("problems", [])
        results.append({"id": case_id, "passed": not diffs, "actual": recorded, "diffs": diffs})

    failed = sum(1 for r in results if not r["passed"])
    summary = {"total": len(results), "passed": len(results) - failed, "failed": failed}
    print(f"run_cases: {summary['passed']}/{summary['total']} passed")
    return finish(
        0 if failed == 0 else 1,
        "passed" if failed == 0 else "failed",
        contract_revision=E.revision,
        pic_commit=E.pin,
        python=platform.python_version(),
        subset=args.cases is not None,
        summary=summary,
        results=results,
    )


if __name__ == "__main__":
    sys.exit(main())
