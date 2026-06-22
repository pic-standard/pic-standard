# Maintainers

This document defines the maintenance roles for the PIC Standard project, identifies the people currently holding those roles, and documents the continuity plan required for the project to survive the loss of any single individual.

---

## Current Maintainers

| Name | GitHub | Role | Contact |
|------|--------|------|---------|
| Fabio Marcello Salvadori | [@madeinplutofabio](https://github.com/madeinplutofabio) | Lead Maintainer | team@madeinpluto.com |

The Lead Maintainer is the primary owner of the repository, releases, security disclosures, and spec freezes. The project is currently single-maintainer; the continuity plan below documents how the project survives loss of the Lead Maintainer.

---

## Role: Maintainer

A Maintainer is responsible for:

- **Code review and merge** — reviewing pull requests against `CONTRIBUTING.md` requirements and merging when CI is green and review consensus is reached.
- **Release management** — cutting releases per `PUBLISH_PYPI.md`, tagging in Git, publishing to PyPI, and updating `CHANGELOG.md`.
- **Security disclosure handling** — receiving and triaging vulnerability reports per `SECURITY.md`, with a 7-day acknowledgment SLA and a 90-day fix target for High/Critical issues.
- **Code of Conduct enforcement** — receiving and acting on conduct reports per `CODE_OF_CONDUCT.md`.
- **Spec stewardship** — managing the DRAFT → cross-implementation conformance → normative trajectory documented in `ROADMAP.md` and the spec status table in `docs/spec-status.md`.
- **Keyring stewardship** — managing the project's published trusted-signer keyring lifecycle (rotation, expiry, revocation) when one is published.
- **Account custodianship** — holding admin rights to the GitHub repository, the PyPI project, and any future infrastructure.

## Role: Contributor

A Contributor is anyone who submits a pull request, opens an issue, files a security advisory, or participates in GitHub Discussions. Contributor expectations are defined in `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`.

---

## Becoming a Maintainer

A Contributor may be invited to become a Maintainer after sustained, substantive contributions over time (typically multiple merged PRs spanning the verifier core, evidence, conformance, or a major integration). The decision is made by the existing Maintainers and announced via a PR adding the new Maintainer to this file.

A new Maintainer is granted, in this order:

1. GitHub `Maintain` role on the repository.
2. PyPI co-owner status on the `pic-standard` project (after demonstrating sustained release-quality contribution).
3. GitHub `Admin` role on the repository (after at least one full release cycle as Maintainer).

---

## Continuity Plan

This project must remain operable if the Lead Maintainer dies, is incapacitated, or is otherwise unable or unwilling to continue. The plan below ensures that issue triage, PR merge, and release publication can resume within **one week** of confirmed loss.

### What "loss of support" means here

Confirmed loss of support means any of: documented incapacity (medical, legal), explicit written resignation, or 30 consecutive days of no response to direct contact attempts on at least two channels (GitHub mention + email).

### Operational continuity

The project's operational surface is intentionally narrow:

| Asset | Provider | Continuity mechanism |
|------|----------|----------------------|
| Source code | GitHub | Apache-2.0 license grants any third party the right to fork and continue. Public Git history is preserved by GitHub and archived independently to Zenodo. |
| Release artifacts (Python wheel, sdist) | PyPI | Published releases are immutable. Future releases require account access (see escrow below). |
| Spec artifact (RFC-0001) | GitHub + Zenodo DOI ([10.5281/zenodo.18725562](https://doi.org/10.5281/zenodo.18725562)) | Defensive publication with SHA-256 fingerprint manifest. Persists independently of any single account. |
| Domain names | None | The project does not own any DNS names. |

### Account access and credential escrow

- **GitHub repository** — the Lead Maintainer holds admin rights. GitHub recovery codes for the `madeinplutofabio` account are held in the sealed continuity envelope described below. Long-lived personal access tokens are not used; CI uses GitHub's built-in `GITHUB_TOKEN` and OIDC.
- **PyPI project** — credentials and project recovery email access are held in the sealed continuity envelope. Migration to PyPI Trusted Publishers (OIDC) is on the project roadmap to remove the long-lived-token failure mode.
- **Project email** — credentials for `team@madeinpluto.com` are held in the sealed continuity envelope.
- **Signing keys** — the project does not currently publish a maintainer signing key. When one is published (per the SECURITY.md known-gap note), the corresponding private key will be added to the sealed continuity envelope.

### Legal continuity

- The repository is licensed **Apache-2.0**, which grants all rights necessary for the project to be forked and continued under new maintainership without requiring permission from the original author or their estate.
- Inbound contributions are governed by Apache-2.0 §5 (inbound = outbound), so the contribution graph requires no further licensing action to continue.
- The project name "PIC Standard" and the GitHub repository under `pic-standard/pic-standard` are not registered trademarks. A successor maintainer may continue under the same name or fork under a new one.

### Designated successor

The Lead Maintainer has designated **Rebecca Yallop** (family member) as the successor authorized to receive account access and act on the project's behalf if the Lead Maintainer becomes unavailable per the definition above.

The successor is not a GitHub user and is not expected to perform technical maintenance personally. Her role is to bridge the access gap between loss of the Lead Maintainer and continuation of the project by a technical successor of her choosing, or — at her discretion — to publish a final release announcing project sunset.

Activation procedure:

1. The successor receives the **sealed continuity envelope** (held privately by the Lead Maintainer, with location and access instructions known to the successor), containing:
   - GitHub account recovery codes for `madeinplutofabio`
   - PyPI account credentials and recovery email access for the `pic-standard` project
   - Credentials for `team@madeinpluto.com`
   - A signed letter from the Lead Maintainer authorizing the successor to act on the project under Apache-2.0
2. Using those credentials, the successor either (a) appoints a technical maintainer of her choice and transfers GitHub repository ownership and PyPI co-owner rights, or (b) publishes a final maintenance release and archives the repository.
3. Apache-2.0 grants any third party the independent right to fork and continue the project, so the successor's authority is not the only path to continuity — it is the path that preserves the official `pic-standard/pic-standard` and PyPI `pic-standard` namespaces.

The successor's contact details are held privately and not published in this file. Verification in a continuity event is via possession of the sealed envelope and recovery codes.

### Activation timeline

If the Lead Maintainer becomes unavailable per the definition above:

1. The designated successor (or any third party acting under Apache-2.0 fork rights) opens a public issue titled "Continuity activation: <date>" documenting the situation.
2. Within 7 days, operational continuity is demonstrated by triaging at least one open issue, merging or closing at least one open PR, and publishing a patch or maintenance release if any is pending.
3. This file is updated in the same week to reflect the new Maintainer roster.

---

## Contact

- **General project questions** — open an issue at <https://github.com/pic-standard/pic-standard/issues>.
- **Security disclosures** — use GitHub Security Advisories per `SECURITY.md`. Do not file public issues for security bugs.
- **Code of conduct** — team@madeinpluto.com per `CODE_OF_CONDUCT.md`.
- **Continuity activation** — open a public issue using the title format above.

---

_This document is reviewed annually and updated as the maintainer roster changes._
