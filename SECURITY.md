# Security Policy

## Supported versions

PIC Standard is pre-1.0; the protocol is still iterating, and only the latest minor release receives security fixes. Older versions receive no patches; users are expected to upgrade to the latest minor on the v0.x line.

| Version | Status                              |
|---------|-------------------------------------|
| 0.8.x   | Supported — security fixes provided |
| < 0.8.0 | End of life — no security fixes     |

Once v1.0 ships and the protocol freezes, the supported-versions policy will be revised in this document.

## Reporting a vulnerability

**Do not file a public GitHub issue for security vulnerabilities.** Public disclosure before a fix lands puts users at risk.

Use **GitHub Security Advisories** (private vulnerability reporting):

1. Go to the repository's **Security** tab on GitHub
2. Click **Report a vulnerability**
3. Fill in the advisory form with the details below

That channel is end-to-end private to the maintainers and produces a coordinated advisory record once the fix lands.

## What to include in a report

- **Affected version(s):** the PIC release(s) you reproduced the issue on (e.g., 0.8.1)
- **Component:** which part of the codebase is affected (e.g., `pic_standard.canonical`, `pic_standard.verifier`, `integrations/openclaw`, conformance vectors)
- **Reproduction:** the smallest input or sequence of operations that triggers the issue — include exact commands, file contents, and environment details if relevant
- **Impact assessment:** what an attacker can do with the issue. Be concrete: information disclosure, signature bypass, denial of service, integrity violation, canonicalization mismatch leading to verification bypass, etc.
- **Suggested mitigation (optional):** if you have a candidate fix or workaround

## Disclosure timeline

PIC Standard is currently maintained by a single author. Best-effort timelines:

- **Acknowledgment:** within **7 days** of submission via GitHub Security Advisories
- **Initial triage:** within **30 days** — severity classification, scope confirmation, fix planning
- **Fix release:** targeted within **90 days** for High/Critical issues; longer for protocol-level issues that may require coordinated changes across implementations
- **Coordinated public disclosure:** default 90 days from acknowledgment, extendable by mutual agreement when fixes require downstream coordination

Reporters are credited in the published advisory unless they explicitly request anonymity.

## Scope

**In scope:**

- `pic-standard` Python package (`sdk-python/pic_standard/`)
- Reference canonicalization implementation (`pic_standard.canonical`)
- Verifier, pipeline, evidence, and keyring modules
- Integration adapters in this repository (`sdk-python/pic_standard/integrations/`)
- Conformance suite and runner (`conformance/`)
- OpenClaw reference plugin (`integrations/openclaw/`)
- Specifications under `docs/` (canonicalization spec, attestation object draft, migration guides)

**Out of scope:**

- Downstream code that imports or depends on PIC Standard
- Third-party plugins, adapters, or implementations not maintained in this repository
- Hosted services that run PIC as a component — report to the operator of the service
- Vulnerabilities whose root cause is in a transitive dependency are typically fixed upstream first; you may report them upstream, but reports are still welcome here when they materially affect PIC Standard users or deployment guidance
- Issues in pre-v0.8.0 releases (end of life)

## Cryptographic signing of communications

PGP-signed reports and acknowledgments are not currently supported — no maintainer signing key has been published. This is a known gap; a maintainer key will be published in this document when one exists. In the interim, the private channel of GitHub Security Advisories is the only supported reporting path.

## Verifying releases

PIC Standard releases produced via the project's release pipeline are cryptographically signed in two complementary ways:

- **PyPI distribution artifacts** (wheel + sdist): signed via [PEP 740 attestations](https://peps.python.org/pep-0740/) (Sigstore-backed, tied to a GitHub Actions Trusted Publisher workflow identity — `pic-standard/pic-standard` running `release.yml` under the `pypi` environment).
- **Git tags**: signed with the project's dedicated Ed25519 release-signing key (the public half is pinned in [`.github/release-signing-key.pub`](.github/release-signing-key.pub)).

For verification commands, the trusted public signing key + SHA256 fingerprint, troubleshooting, and key rotation procedure, see **[`RELEASING.md`](RELEASING.md)**.

Releases predating the signing infrastructure are unsigned legacy artifacts. The cutover version is documented in `RELEASING.md`.
