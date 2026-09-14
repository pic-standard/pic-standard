"""
Unit tests for pic_standard.canonical — the PIC Canonical JSON v1 (PIC-CJSON/1.0)
reference implementation.

Scope:
  * Vector sweep across every file in conformance/canonicalization/ (the portable
    conformance vectors — cross-language-consumable, byte-exact).
  * Implementation-local rejection cases per docs/canonicalization.md §10.1.
    These inputs are non-representable as portable JSON values (non-finite
    numbers, non-string dict keys, circular refs, lone surrogates, host types
    with no JSON mapping, Python tuples, out-of-range integers) and therefore
    cannot live in shared vector files — they are tested here instead.
  * Host-representation-dependent positive behaviours (negative zero).
  * sha256_hex convenience.
  * intent_digest_hex and its §8.3-vs-§8.1/§8.2 distinction from sha256_hex.

This file is part of Step 4 of the v0.8.0 canonicalization plan and is the
regression gate that catches drift in the reference implementation.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import pytest
from pic_standard.canonical import (
    CanonicalizationError,
    canonicalize,
    intent_digest_hex,
    sha256_hex,
)

# ---------------------------------------------------------------------------
# Conformance vector sweep
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CANON_VECTOR_DIR = _REPO_ROOT / "conformance" / "canonicalization"


def _load_canonicalization_vectors():
    """Discover every canon-NNN-*.json vector in sorted order for parametrization."""
    params = []
    for path in sorted(_CANON_VECTOR_DIR.glob("[0-9][0-9][0-9]_*.json")):
        with path.open("r", encoding="utf-8") as f:
            vec = json.load(f)
        params.append(pytest.param(vec, id=vec["id"]))
    return params


@pytest.mark.parametrize("vector", _load_canonicalization_vectors())
def test_canonicalization_vector(vector):
    """
    Each conformance vector under conformance/canonicalization/ must be
    handled per its declared shape:

    - Positive (canonical_match) vectors carry ``expected_canonical_bytes_hex``
      and ``expected_sha256_hex``; canonicalize() MUST produce exactly those
      bytes and the SHA-256 MUST match.
    - Negative (canonical_reject) vectors omit those fields; canonicalize()
      MUST raise CanonicalizationError on the vector's ``input``.

    Shape is inferred from the presence of the expected fields so this
    sweep stays in sync with vector files without depending on
    conformance/manifest.json. Primary correctness gate for PIC-CJSON/1.0
    reference compliance.
    """
    has_expected_bytes = "expected_canonical_bytes_hex" in vector
    has_expected_sha = "expected_sha256_hex" in vector

    assert has_expected_bytes == has_expected_sha, (
        f"canonicalization vector {vector['id']} must define both "
        "`expected_canonical_bytes_hex` and `expected_sha256_hex`, or neither"
    )

    if has_expected_bytes:
        actual_bytes = canonicalize(vector["input"])
        assert actual_bytes.hex() == vector["expected_canonical_bytes_hex"], (
            f"canonical bytes mismatch for {vector['id']}\n"
            f"  actual:   {actual_bytes.hex()}\n"
            f"  expected: {vector['expected_canonical_bytes_hex']}"
        )
        actual_sha = hashlib.sha256(actual_bytes).hexdigest()
        assert actual_sha == vector["expected_sha256_hex"], (
            f"SHA-256 mismatch for {vector['id']}\n"
            f"  actual:   {actual_sha}\n"
            f"  expected: {vector['expected_sha256_hex']}"
        )
    else:
        with pytest.raises(CanonicalizationError):
            canonicalize(vector["input"])


def test_vector_sweep_nonempty():
    """
    Guard against regressions in vector discovery. If the loader glob ever
    stops matching any files, parametrization would silently run zero
    vectors and the sweep would pass vacuously. This test asserts the
    directory is actually producing work. Exact count is deliberately NOT
    asserted — intentional future vector additions should not require
    updating this guard. The precise count is pinned by the manifest
    (conformance/manifest.json) once the conformance runner lands.
    """
    vectors = _load_canonicalization_vectors()
    assert len(vectors) > 0, f"no canonicalization vectors discovered at {_CANON_VECTOR_DIR}"


# ---------------------------------------------------------------------------
# canonicalize() — happy-path edge cases
# ---------------------------------------------------------------------------


def test_canonicalize_empty_dict():
    assert canonicalize({}) == b"{}"


def test_canonicalize_empty_list():
    assert canonicalize([]) == b"[]"


def test_canonicalize_empty_string():
    assert canonicalize("") == b'""'


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, b"null"),
        (True, b"true"),
        (False, b"false"),
        (0, b"0"),
        (1, b"1"),
        (-1, b"-1"),
        ("hello", b'"hello"'),
    ],
)
def test_canonicalize_top_level_primitives(value, expected):
    """Top-level canonicalize works for each JSON primitive type."""
    assert canonicalize(value) == expected


def test_canonicalize_accepts_max_safe_integer():
    """2^53 - 1 is the largest integer representable exactly by IEEE 754 double."""
    assert canonicalize(2**53 - 1) == b"9007199254740991"


def test_canonicalize_accepts_min_safe_integer():
    """-(2^53 - 1) is the safe-range lower bound per RFC 8785."""
    assert canonicalize(-(2**53 - 1)) == b"-9007199254740991"


def test_canonicalize_negative_zero_serializes_as_zero():
    """
    §7.9: canonical serialization of negative zero yields '0', not '-0' or '-0.0'.
    This is a host-representation-dependent positive behaviour (see the README
    'What is NOT covered here' section) tested here rather than in vectors,
    because portable JSON parsers do not uniformly preserve the -0/+0 distinction.
    """
    neg_zero = -0.0
    pos_zero = 0.0
    assert canonicalize(neg_zero) == b"0"
    assert canonicalize(pos_zero) == b"0"
    assert canonicalize(neg_zero) == canonicalize(pos_zero)


# ---------------------------------------------------------------------------
# canonicalize() — rejection cases (§10.1 implementation-local)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_number",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        math.nan,
        math.inf,
        -math.inf,
    ],
)
def test_canonicalize_rejects_non_finite_numbers(bad_number):
    """§7.9: NaN, +Infinity, -Infinity are not representable in JSON and must be rejected."""
    with pytest.raises(CanonicalizationError):
        canonicalize(bad_number)
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": bad_number})
    with pytest.raises(CanonicalizationError):
        canonicalize([1, bad_number, 2])


@pytest.mark.parametrize(
    "bad_key",
    [
        1,
        1.5,
        None,
        True,
        (1, 2),
        b"bytes_key",
        frozenset([1, 2]),
    ],
)
def test_canonicalize_rejects_non_string_keys(bad_key):
    """§7.3: object member names MUST be strings."""
    with pytest.raises(CanonicalizationError):
        canonicalize({bad_key: "value"})


def test_canonicalize_rejects_non_string_key_even_if_it_implements_encode():
    """
    Regression guard for the PIC-owned §7.3 enforcement boundary.

    The upstream rfc8785 detects non-string keys indirectly — it calls
    ``key.encode('utf-16be')`` during the sort-key computation and catches
    AttributeError when that fails. A host-language class that happens to
    implement its own ``.encode(...)`` method would slip past the upstream
    AttributeError check and produce canonical output with a key that is
    not in fact a JSON string — silently violating §7.3.

    PIC's ``canonicalize()`` wrapper therefore performs its own
    ``isinstance(key, str)`` check before dispatching to the vendored code.
    This test pins that check so a future "simplifying" refactor that
    removes the PIC-side check cannot land without this test failing.
    """

    class SneakyKey:
        def encode(self, *_args, **_kwargs):
            return b"fake"

        def __repr__(self):
            return "SneakyKey()"

    with pytest.raises(CanonicalizationError):
        canonicalize({SneakyKey(): "value"})


def test_canonicalize_rejects_circular_dict():
    """Circular reference among host-language objects is non-conformant."""
    obj: dict = {}
    obj["self"] = obj
    with pytest.raises(CanonicalizationError):
        canonicalize(obj)


def test_canonicalize_rejects_circular_list():
    arr: list = [1, 2, 3]
    arr.append(arr)
    with pytest.raises(CanonicalizationError):
        canonicalize(arr)


def test_canonicalize_rejects_mutual_circular():
    a: dict = {}
    b: dict = {"a": a}
    a["b"] = b
    with pytest.raises(CanonicalizationError):
        canonicalize(a)


def test_canonicalize_rejects_top_level_tuple():
    """
    PIC wrapper rule: Python tuples are rejected to surface intent ambiguity.
    The upstream rfc8785 accepts tuples as lists, but PIC's canonicalize()
    rejects them to match the explicit list-vs-tuple-is-distinct-type
    philosophy of the spec.
    """
    with pytest.raises(CanonicalizationError):
        canonicalize((1, 2, 3))


def test_canonicalize_rejects_nested_tuple_in_dict():
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": (1, 2, 3)})


def test_canonicalize_rejects_tuple_in_list():
    with pytest.raises(CanonicalizationError):
        canonicalize([1, (2, 3), 4])


@pytest.mark.parametrize(
    "bad_value",
    [
        {1, 2, 3},
        object(),
        complex(1, 2),
        b"bytes",
        bytearray(b"bytes"),
    ],
)
def test_canonicalize_rejects_non_serializable_host_types(bad_value):
    """Host-language types with no natural JSON mapping are non-conformant."""
    with pytest.raises(CanonicalizationError):
        canonicalize(bad_value)
    with pytest.raises(CanonicalizationError):
        canonicalize({"x": bad_value})


def test_canonicalize_rejects_lone_surrogate_in_key():
    """§7.13: keys containing lone surrogate code points are non-conformant."""
    with pytest.raises(CanonicalizationError):
        canonicalize({chr(0xD800): "value"})  # unpaired high surrogate


def test_canonicalize_rejects_lone_surrogate_in_string_value():
    """§7.13: string values containing lone surrogates cannot encode to UTF-8."""
    with pytest.raises(CanonicalizationError):
        canonicalize({"key": chr(0xD800)})
    with pytest.raises(CanonicalizationError):
        canonicalize(chr(0xDC00))  # unpaired low surrogate, top-level


def test_canonicalize_rejects_integer_exceeding_safe_range_positive():
    """§7.9: integers > 2^53 - 1 are outside IEEE 754 exact-integer range."""
    with pytest.raises(CanonicalizationError):
        canonicalize(2**53)


def test_canonicalize_rejects_integer_exceeding_safe_range_negative():
    """§7.9: integers < -(2^53 - 1) are outside IEEE 754 exact-integer range."""
    with pytest.raises(CanonicalizationError):
        canonicalize(-(2**53))


# ---------------------------------------------------------------------------
# sha256_hex() — convenience hash over canonicalize output
# ---------------------------------------------------------------------------


def test_sha256_hex_matches_canon_001_vector():
    """
    sha256_hex spot-check: the §9.1 worked example input produces the SHA-256
    pinned in docs/canonicalization.md §9.1 and in conformance vector 001.
    """
    result = sha256_hex({"b": 2, "a": 1})
    expected = "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
    assert result == expected


def test_sha256_hex_returns_64_lowercase_hex():
    result = sha256_hex({"a": 1})
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result), (
        f"sha256_hex returned non-lowercase-hex characters: {result}"
    )


def test_sha256_hex_propagates_canonicalization_errors():
    """
    sha256_hex is a thin wrapper over canonicalize; rejection cases from
    canonicalize must surface as CanonicalizationError from sha256_hex too.
    """
    with pytest.raises(CanonicalizationError):
        sha256_hex(float("nan"))


# ---------------------------------------------------------------------------
# intent_digest_hex() — §8.3 raw-UTF-8 path, distinct from §8.1 / §8.2
# ---------------------------------------------------------------------------


def test_intent_digest_hex_happy_path():
    """A normal intent string returns a 64-char lowercase hex digest."""
    result = intent_digest_hex("Pay invoice INV-001 for $50")
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_intent_digest_hex_returns_64_lowercase_hex():
    result = intent_digest_hex("hello")
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


def test_intent_digest_hex_differs_from_sha256_hex():
    """
    §8.3 bug trap: intent_digest_hex hashes raw UTF-8 bytes of the intent
    string; sha256_hex hashes the canonical JSON bytes (which include the
    surrounding quotes). The two MUST produce different digests for the
    same string input. This assertion makes the trap visible at the
    assert level if anyone ever collapses the two helpers.
    """
    assert sha256_hex("hello") != intent_digest_hex("hello")


def test_intent_digest_hex_equals_sha256_of_raw_utf8():
    """
    Explicit identity: intent_digest_hex('hello') == sha256(b'hello').hexdigest().
    §8.3 says the digest is over the UTF-8 bytes of the intent string without
    JSON wrapping.
    """
    expected = hashlib.sha256(b"hello").hexdigest()
    assert intent_digest_hex("hello") == expected


def test_sha256_hex_of_string_equals_sha256_of_quoted_utf8():
    """
    Complementary identity: sha256_hex('hello') == sha256(b'"hello"').hexdigest().
    The canonical JSON form of the bare string 'hello' is '"hello"' (5 chars
    plus 2 quotes, 7 bytes), so sha256_hex hashes 7 bytes, not 5.
    """
    expected = hashlib.sha256(b'"hello"').hexdigest()
    assert sha256_hex("hello") == expected


def test_intent_digest_hex_rejects_lone_surrogate():
    """§7.13: an intent string carrying a lone surrogate is non-conformant."""
    with pytest.raises(CanonicalizationError):
        intent_digest_hex(chr(0xD800))
    with pytest.raises(CanonicalizationError):
        intent_digest_hex("prefix" + chr(0xDC00) + "suffix")


@pytest.mark.parametrize(
    "bad_input",
    [
        123,
        1.5,
        None,
        True,
        b"hello",
        ["hello"],
        {"text": "hello"},
        ("hello",),
    ],
)
def test_intent_digest_hex_rejects_non_str(bad_input):
    """
    intent_digest_hex MUST raise CanonicalizationError on non-str inputs, NOT
    leak AttributeError from a bare '.encode()' call or TypeError from hashlib.
    This is a type-check boundary at the PIC wrapper layer: the function is
    narrowly scoped to §8.3 intent strings and refuses anything else at the
    door rather than letting the error originate deeper in the call stack.
    """
    with pytest.raises(CanonicalizationError):
        intent_digest_hex(bad_input)


def test_intent_digest_hex_handles_unicode_in_intent():
    """Intent strings with non-ASCII characters hash per their UTF-8 bytes."""
    result = intent_digest_hex("Transferir €50 a proveedor")
    expected = hashlib.sha256("Transferir €50 a proveedor".encode("utf-8")).hexdigest()
    assert result == expected


def test_intent_digest_hex_handles_empty_string():
    """Empty intent string hashes to SHA-256 of zero bytes."""
    result = intent_digest_hex("")
    expected = hashlib.sha256(b"").hexdigest()
    assert result == expected
