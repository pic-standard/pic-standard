# Adding a conformance vector — contributor guide

New to PIC? Adding a conformance vector is the best first contribution: it's
self-contained, has a clear pass/fail finish line, and directly strengthens the
spec. This guide walks you through one end to end. No prior knowledge of the
codebase needed.

## What a conformance vector is

A **vector** is a single JSON file that pins one expected behaviour of the PIC
verifier — e.g. "a money-impact proposal from an untrusted source with no evidence
MUST be blocked." The suite is the executable contract every PIC implementation
(Python today, TypeScript/Go next) must satisfy. Every vector is listed in
`conformance/manifest.json` and run by `conformance/run.py`.

There are four **modes**, each with its own directory and README:

| Mode | Directory | What it checks |
|---|---|---|
| `core` | `conformance/core/` | allow/block decisions of the verifier |
| `canonicalization` | `conformance/canonicalization/` | byte-exact JSON canonical form |
| `evidence` | `conformance/evidence/` | hash/signature evidence verification |
| `trust_sanitization` | `conformance/trust_sanitization/` | `strict_trust` behaviour |

**Best first target:** a `core` allow or block vector (issues #44, #45). This guide
uses `core` as the example; the per-mode READMEs cover the specifics for the others.

## Prerequisites (one-time)

```bash
git clone https://github.com/pic-standard/pic-standard.git
cd pic-standard
pip install -e "./sdk-python"      # makes pic_standard importable
python -m conformance.run          # confirm the suite runs green before you start
```

## Step 1 — Pick the behaviour and find a source

Every core vector must **pin a rule**, not just snapshot today's output. Decide:
- **Origin** — where the proposal comes from: an existing `examples/*.json`, a fixture
  in `tests/conftest.py`, or a hand-authored proposal (with a one-line rationale).
- **Rule** — the normative verifier rule you're locking in.

You'll record both in the vector's `source` field (see Step 2).

## Step 2 — Create the vector file

Files are named `NNN_<slug>.json` with a zero-padded counter, in `allow/` or `block/`.
Find the next free number:

```bash
ls conformance/core/allow/      # e.g. highest is 002_... → yours is 003
```

Create `conformance/core/allow/003_<slug>.json`. Copy the shape of an existing one
([`core/allow/001_read_only.json`](core/allow/001_read_only.json) is the simplest):

```json
{
  "id": "core-allow-003-<slug>",
  "description": "One sentence: what verifier behaviour this pins.",
  "source": "adapted from examples/<x>.json; exercises the causal rule that <rule>",
  "expected": "allow",
  "proposal": {
    "protocol": "PIC/1.0",
    "intent": "...",
    "impact": "read",
    "provenance": [ { "id": "src", "trust": "untrusted" } ],
    "claims": [ { "text": "...", "evidence": ["src"] } ],
    "action": { "tool": "some.tool", "args": { } }
  }
}
```

For a **block** vector, set `"expected": "block"` and add the exact
`"expected_error_code"` produced by the reference verifier for that rule. Do not
guess the code: run the filtered vector, inspect the failure, and use the specific
code from `sdk-python/pic_standard/errors.py` or the nearest existing vector. Full
field semantics: [`conformance/core/README.md`](core/README.md).

## Step 3 — Register it in the manifest

Add an entry to `conformance/manifest.json` (`vectors` array). **A vector file with no
manifest entry is never run.** Match the file exactly:

```json
{
  "id": "core-allow-003-<slug>",
  "file": "core/allow/003_<slug>.json",
  "mode": "core",
  "expected": "allow"
}
```

(Block entries also need `"expected_error_code"`.)

## Step 4 — Run it and confirm it passes

```bash
python -m conformance.run --filter-id core-allow-003-<slug> --verbose
```

Expect `PASS`. If it fails, the runner tells you exactly why (verdict mismatch, wrong
error code, manifest/file drift, etc.). Then run the whole suite to be sure you didn't
break anything:

```bash
python -m conformance.run
```

> The `expected` outcome MUST match what the reference implementation actually does —
> confirm against `verify_proposal()` before committing. If you believe the
> implementation is wrong (not your vector), say so in the PR: that's a spec discussion,
> which is exactly what this suite is for.

## Step 5 — Open the PR

```bash
git checkout -b vector/core-allow-003-<slug>
git add conformance/
git commit -s -m "test(conformance): add core-allow-003-<slug> vector"   # -s = DCO sign-off
git push -u origin vector/core-allow-003-<slug>
```

Open the PR; CI runs the conformance job automatically. Comment on the issue you're
addressing so we know it's taken.

## Pre-PR checklist

- [ ] File in the right `allow/`/`block/` directory, named `NNN_<slug>.json`
- [ ] `id` is identical in the file and the manifest entry
- [ ] `source` names both an **origin** and a **rule**
- [ ] `expected` (+ `expected_error_code` for blocks) matches `verify_proposal()`
- [ ] `python -m conformance.run` is fully green
- [ ] Commit is signed off (`git commit -s`)

## Need help?

Comment on your issue and tag the maintainer — mentoring is offered. Deeper rules per
mode: [`core`](core/README.md), [`canonicalization`](canonicalization/README.md),
[`evidence`](evidence/README.md), [`trust_sanitization`](trust_sanitization/README.md).
