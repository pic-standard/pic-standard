# Contributing to the PIC Standard

Thank you for helping us build a more accountable future for AI. 🛡️

## ✍️ Developer Certificate of Origin (DCO)

PIC Standard uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO) for individual contributions. All commits to this repository **must be signed off** under the DCO. The DCO is a lightweight, per-commit attestation that you have the right to submit the contribution under the project's Apache 2.0 license.

**Scope note:** The DCO covers contributor attestation on individual commits. If the project is accepted into a hosting foundation or formal open-governance program, additional project-level onboarding or contribution agreements may apply as required by that program. The DCO does not replace such agreements; it complements them.

### How to sign off

Add the `-s` flag to your commits:

```bash
git commit -s -m "Your commit message"
```

This appends a `Signed-off-by:` line to the commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use the **real name and email** associated with your GitHub account. Anonymous or pseudonymous sign-offs are not accepted.

### What the DCO certifies

By signing off, you certify that:

- You created the contribution yourself and have the right to submit it under Apache 2.0, **or**
- The contribution is based on previous work covered under an appropriate open-source license that allows submission under Apache 2.0 (with that license preserved in the contribution), **or**
- The contribution was provided to you by someone who certified one of the above, and you are passing it through unmodified

See [developercertificate.org](https://developercertificate.org/) for the full text.

### CI enforcement

The DCO sign-off is checked by the **DCO GitHub App** on every pull request. PRs without `Signed-off-by:` on every commit cannot be merged. The check appears under the PR's status checks.

### Fixing commits that lack sign-off

If you already pushed commits without sign-off, you can amend the last commit:

```bash
git commit --amend --signoff
git push --force-with-lease
```

Or re-sign multiple commits at once:

```bash
git rebase HEAD~N --signoff   # N = number of commits to re-sign
git push --force-with-lease
```

The DCO App will re-check the PR automatically after the push.

## 🛠️ How to Contribute

### 1. Proposing a New Impact Class
If your domain (e.g., Healthcare, Legal) requires specific risk controls:
1. Use the **New Impact Class** issue template.
2. Define the risk levels and required **Evidence Requirements**.

### 2. Requirements for Acceptable Contributions

- All code must pass the existing test suite and conformance tests (`pytest` + `conformance.yml` workflow).
- **Style is enforced by automated tools — CI blocks merge on violations.**
  - **Python** (Ruff): config in `pyproject.toml` (`[tool.ruff]`); rule set `E F W I N B SIM RUF`.
    Run locally before pushing:

    ```bash
    ruff check sdk-python/ tests/ conformance/
    ruff format --check sdk-python/ tests/ conformance/
    ```

  - **TypeScript** (ESLint v9 flat config + Prettier): config in `integrations/openclaw/{eslint.config.mjs, .prettierrc.json}`.
    Run locally before pushing:

    ```bash
    cd integrations/openclaw
    npm run lint
    npm run format:check
    ```

- **Statement coverage ≥80% (Python codebase only).** CI runs `python -m coverage report --fail-under=80` for the Python SDK (`sdk-python/pic_standard/`). TypeScript integration coverage is deferred to a v0.9.x follow-up. Config: `pyproject.toml` (`[tool.coverage.run]` / `[tool.coverage.report]`).
- Pull requests must include a clear description of the change and reference any related issue or discussion.
- For SDK changes, all Pydantic models must validate successfully.

### 3. Implementation & SDKs
We are currently focusing on the Python Reference SDK. If you wish to contribute:
1. Fork the repository.
2. Ensure all Pydantic models in `sdk-python/` pass validation.
3. Submit a PR with a clear description of changes.

**Adding a conformance vector?** See the step-by-step guide: [`conformance/adding-a-vector.md`](conformance/adding-a-vector.md).

## 4. Test Policy

Pull requests that add or change behavior MUST include automated tests
for that behavior. Specifically:

- New public APIs, new pipeline stages, new evidence types, new policy
  knobs, and new integrations MUST ship with unit tests under `tests/`.
- New verifier behavior MUST also ship with conformance vectors under
  `conformance/` where applicable.
- Bug fixes MUST include a regression test that fails before the fix
  and passes after.
- Documentation-only and refactor-only PRs (no behavior change) are
  exempt.

Maintainers will not merge PRs that add new functionality without
corresponding tests.

## 5. Branch Protection on `main`

The `main` branch is protected by the `Main Protection` repository
ruleset. Every merge into `main` requires:

- An open pull request; direct pushes to `main` are blocked.
- All 7 required status checks passing: `test-python (3.10, pinned)`,
  `test-python (3.11, pinned)`, `test-python (3.12, pinned)`,
  `test-python (3.12, latest)`, `test-openclaw`, `Conformance vectors`,
  and `DCO`.
- The PR branch up to date with `main` before merge (strict mode).
- Squash-merge only; merge commits and rebase-merges are disabled.
- Branch deletion and force-pushes blocked.
- No bypass; admins are subject to the same rules.

Tag protection for release tags is documented separately in
`RELEASING.md`.

## ⚖️ Governance Model
The PIC Standard is consensus-driven. Major changes to the core `spec/` or `schemas/` must be initiated in the **GitHub Discussions** tab before a Pull Request is opened.

## 🔑 Release Process

**All release tags MUST be signed** with the project's dedicated SSH release-signing key. This is not just policy — the release workflow (`.github/workflows/release.yml`) verifies the tag's signature against the trusted public key in `.github/release-signing-key.pub` before any artifact is built. Unsigned or wrongly-signed tags are rejected; no PyPI upload or GitHub Release happens for them.

Full setup and release flow:

- Signing key generation, git config, GitHub Signing Key registration: see `RELEASING.md` (Prerequisites section).
- Release flow (`git tag -s` → push → approval gate → automated publish): see `RELEASING.md` (For maintainers section).
- Trusted public key + SHA256 fingerprint: see `RELEASING.md` (Trusted public signing key section).

New maintainers should complete the one-time setup before cutting their first release.

## 📜 Code of Conduct
Please be professional and inclusive. We follow the Contributor Covenant.
