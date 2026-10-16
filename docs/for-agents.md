# Evaluate and integrate PIC Standard

PIC Standard (Provenance & Intent Contracts) verifies structured action proposals before an AI agent's tool call executes. Use it when a tool gateway needs to check declared intent, impact, provenance and supporting evidence before permitting an action. The Python implementation runs locally and is Apache-2.0 licensed.

This guide helps you choose an implementation, run a small verification example, and find the integration appropriate to your task.

## Choose a path

| Your task | Start here |
|---|---|
| Verify signed evidence before a payment, data export or destructive tool call | Python verification pipeline and [evidence guide](https://github.com/pic-standard/pic-standard/blob/main/docs/evidence.md) |
| See a complete signed-approval example with argument binding and 22 verification + dispatch cases | [`examples/refund-approval`](https://github.com/pic-standard/pic-standard/tree/main/examples/refund-approval) |
| Follow a CLI walkthrough that verifies a valid signed proposal and a tampered one | [`examples/walkthroughs/signature-evidence.md`](https://github.com/pic-standard/pic-standard/blob/main/examples/walkthroughs/signature-evidence.md) |
| Guard tools exposed by a Python MCP server | [MCP integration](https://github.com/pic-standard/pic-standard/blob/main/docs/mcp-integration.md) |
| Gate a LangGraph tool node | `PICToolNode`; see [integrations](https://github.com/pic-standard/pic-standard#integrations) |
| Request evidence verification from a non-Python service | Python [HTTP bridge contract](https://github.com/pic-standard/pic-standard/blob/main/openapi/pic-bridge.v1.yaml) and [deployment guide](https://github.com/pic-standard/pic-standard/blob/main/docs/deploy-docker.md) |
| Add PIC to OpenClaw or Cordum | [OpenClaw guide](https://github.com/pic-standard/pic-standard/blob/main/docs/openclaw-integration.md) or [Cordum guide](https://github.com/pic-standard/pic-standard/blob/main/docs/cordum-integration.md) |

Python requires 3.10 or later. Ed25519 verification requires the `crypto` extra. MCP and LangGraph have separate optional extras. Local verification does not require a hosted PIC account or a model API key. The application supplies its own policy, trusted public keys and any credentials needed to execute tools.

A TypeScript implementation exists at [pic-standard/pic-standard-ts](https://github.com/pic-standard/pic-standard-ts) covering `canonicalization`, `core` and `trust_sanitization` modes. Signature verification and evidence-derived trust are a current capability gap in TypeScript, planned for completion in the v0.9.x series. Use the Python implementation (or the Python HTTP bridge from a Node.js caller) when those features are needed.

## What an allow result establishes

An allow result means the proposal passed the checks enabled for that call. The verifier does not execute the action or establish that it subsequently succeeded.

With the secure default, incoming `provenance[].trust` values are sanitized to `untrusted`. Verified signature evidence can upgrade matching provenance through the configured trusted keyring. A matching file hash establishes integrity of the referenced bytes; it does not establish authority or upgrade trust by itself.

The core high-impact categories are `money`, `privacy` and `irreversible`. Integrations should assign impact using operator-controlled tool policy rather than relying on the agent's classification alone.

PIC does not determine whether a natural-language claim is true, whether a signer made a sensible business decision, or whether the declared provenance lists every influence on the model. It is not an identity provider, sandbox, payment processor or complete compliance solution. Enforcement requires the actual execution path to respect the decision and prevent bypass.

## Try verification without executing a tool

Use a repository checkout because these fixture files are repository assets. From the checkout root, create and activate a virtual environment, then install the inspected source:

```bash
python -m pip install -e ".[crypto]"
```

Run the following Python code from that same directory:

```python
import json
import os
from pathlib import Path

from pic_standard.pipeline import PipelineOptions, verify_proposal

root = Path.cwd()
os.environ["PIC_KEYS_PATH"] = str(root / "pic_keys.example.json")

cases = [
    ("examples/financial_sig_ok.json", True),
    ("examples/failing/financial_sig_bad.json", False),
]

for relative_path, expected_ok in cases:
    path = root / relative_path
    proposal = json.loads(path.read_text(encoding="utf-8"))
    result = verify_proposal(
        proposal,
        options=PipelineOptions(
            expected_tool="payments_send",
            verify_evidence=True,
            strict_trust=True,
            proposal_base_dir=path.parent,
            evidence_root_dir=path.parent,
        ),
    )
    print(relative_path, result.ok, result.error.code.value if result.error else None)
    assert result.ok is expected_ok
```

Expected output:

```text
examples/financial_sig_ok.json True None
examples/failing/financial_sig_bad.json False PIC_EVIDENCE_FAILED
```

Neither call executes a payment. The demo signing keys expire on 1 January 2027; after expiry, the positive fixture will also fail. Use operator-managed keys for an integration.

These fixtures use legacy signing: the signature covers the inline evidence payload, not the entire action or its arguments. They demonstrate signature verification, not complete approval-to-action binding.

For a complete runnable example of PIC-ATT/1.0 canonical signing with argument binding, inspect [`examples/refund-approval`](https://github.com/pic-standard/pic-standard/tree/main/examples/refund-approval). It signs an exact refund action, verifies the canonical attestation, enforces a workflow profile (tool, impact, args schema, expiry, merchant-claim schema) before dispatch, and runs 22 verification and dispatch cases with tool-call accounting, spy-args assertions and integrity meta-tests. For the normative contract, see [the evidence specification](https://github.com/pic-standard/pic-standard/blob/main/docs/spec-evidence.md) and the [canonical evidence vectors](https://github.com/pic-standard/pic-standard/tree/main/conformance/evidence). Follow the supported field requirements; optional binding fields do not provide protection when absent.

## Put the decision at the execution boundary

1. Let the application select the actual tool and its impact policy. Pass that tool's name as `expected_tool`; deriving it from the proposal itself would not independently check the destination.
2. Keep strict trust enabled, enable evidence verification where required, and configure trusted keys and evidence requirements outside agent-controlled input.
3. Ensure the arguments actually dispatched match the verified action. Tool-name matching alone does not bind a separate set of execution arguments. The `examples/refund-approval` wrapper demonstrates one way to enforce this at the integration boundary.
4. Execute only after a successful decision. Treat errors, unavailable verification and non-allow outcomes as reasons not to execute.
5. Implement approval consumption, replay prevention, provider idempotency and execution reconciliation in the surrounding application when needed. An unexpired signature does not by itself make an approval single-use.

The Python pipeline returns `PipelineResult.ok` and an optional error. The HTTP bridge returns `allowed` and an optional error; an HTTP 200 response can contain `allowed: false`. Do not treat transport success as permission. The bridge verifies requests; the caller remains responsible for gating execution.

## Find the exact contract

- [Specification status](https://github.com/pic-standard/pic-standard/blob/main/docs/spec-status.md): distinguishes the frozen RFC and canonicalization specification from draft Core, Evidence and Attestation documents. `PIC/1.0` is a protocol identifier, not a claim that the package is version 1.0.
- [Error reference](https://github.com/pic-standard/pic-standard/blob/main/docs/ERRORS.md): programmatic failure codes.
- [Keyring](https://github.com/pic-standard/pic-standard/blob/main/docs/keyring.md): trusted signers, expiry, revocation and custom resolvers.
- [Conformance manifest](https://github.com/pic-standard/pic-standard/blob/main/conformance/manifest.json): executable cases and their modes. From an installed checkout, run `python -m conformance.run --json`.
- [Contributing](https://github.com/pic-standard/pic-standard/blob/main/CONTRIBUTING.md): development and submission instructions.

For a reproducible evaluation, record the checkout commit, installed package version, selected conformance modes and configuration. Use documentation from that same revision; roadmap entries are not implemented capabilities.
