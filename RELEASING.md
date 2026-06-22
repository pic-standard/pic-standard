# Releasing pic-standard

This document describes how releases of `pic-standard` are produced, signed, and verified.

It is intended for two audiences:

- **Maintainers** who cut releases. The flow is `git tag -s` → `git push` → maintainer-approves the deploy → PyPI + GitHub Release are produced automatically.
- **Users and downstream consumers** who want to verify cryptographically that a release artifact (PyPI wheel/sdist or git tag) was produced by the project's authorized release pipeline.

---

## Trust model: two cryptographically-verifiable layers

The release pipeline produces two distinct signed artifacts, verifiable through two distinct paths:

### Layer 1: PyPI distribution artifacts (wheel + sdist)

Built and uploaded to PyPI by `.github/workflows/release.yml`. Each upload is accompanied by a **PEP 740 attestation** — a Sigstore-issued, transparency-logged signature binding the artifact bytes to a specific GitHub Actions workflow identity (`pic-standard/pic-standard`, workflow `release.yml`, environment `pypi`).

- **What proves authenticity:** PyPI publishes the attestation alongside the artifact. The Sigstore-issued certificate is short-lived (per-workflow-run, ephemeral) but cryptographically tied to a GitHub Actions OIDC token claim that asserts "this workflow ran in this repo from this environment." Trust roots back to GitHub's OIDC issuer + Sigstore's public transparency log.
- **What you do to verify:** install `pypi-attestations` (a FLOSS CLI from PyPA), point it at the artifact, and the tool fetches the attestation from PyPI and validates the entire chain. See "For users" below for the command.
- **No long-lived artifact-signing public key.** This is the modern PEP 740 model: ephemeral keys per workflow run, anchored by GitHub identity + Sigstore.

### Layer 2: Git tags

Created locally by the maintainer using `git tag -s`, signed with the project's dedicated **long-lived SSH release-signing key** (Ed25519). The public half is published in this repository at `.github/release-signing-key.pub` and pinned in this document.

- **What proves authenticity:** the tag carries an OpenSSH signature over the tag's metadata. Verification compares the signature against the published public key; if they match, the tag was signed by whoever holds the corresponding private key (the maintainer).
- **What you do to verify:** download the published public key, populate a local `allowed_signers` file, and run `git tag -v <tag-name>`. GitHub also auto-displays a "Verified" indicator on signed tags in the Releases → Tags view (server-side check against the maintainer's registered Signing Key).
- **Classic long-lived key model.** The same public key is reused across all releases until explicit rotation (see "Key rotation" below).

Both layers run for every release. If either verification fails, treat the release as **unverified** until the discrepancy is resolved.

---

## For maintainers

### Cutting a release

From a clean checkout of `main` at the commit you want to release:

```bash
# 1. Create an annotated, signed tag. `git tag -s` automatically signs with
#    the SSH release-signing key (per the repo's git config — see Prerequisites).
#    The -m message becomes the GitHub Release body (release notes).
git tag -s v<version> -m "v<version>: <human-readable release notes>

<longer body, multi-line OK>"

# 2. Push the tag. This triggers .github/workflows/release.yml.
git push origin v<version>
```

The annotated tag's message is used **verbatim** as the GitHub Release body. Write release notes that humans can read — change summary, breaking changes, migration notes, etc. Do not paste raw commit logs.

### What happens after `git push`

1. **Workflow triggers** on the `v*` tag push. The `verify-and-build` job starts immediately.
2. **Signature verification** runs (`git tag -v <tag>` against `.github/release-signing-key.pub`). If unsigned or signed by an unknown key, the workflow aborts here — no artifact is built.
3. **Build** runs `python -m build`, producing `dist/<name>-<version>.whl` and `dist/<name>-<version>.tar.gz`.
4. **Approval gate fires** on the `publish` job (the `pypi` GitHub Environment requires reviewer approval). You'll get a GitHub notification; visit the Actions UI and click "Approve" to proceed.
5. **Publish** uploads the wheel + sdist to PyPI via Trusted Publisher (OIDC, no API token). PEP 740 attestations are generated and uploaded automatically by `pypa/gh-action-pypi-publish` when using Trusted Publisher.
6. **GitHub Release** is created with the annotated tag's body as the release body and the built artifacts attached.

If anything fails after approval, you'll see the failure in the Actions UI. The most common late-stage failure is a PyPI rejection (e.g., version already exists), which means you need to bump the version and re-tag.

### Prerequisites (one-time setup)

Local git must be configured to sign tags with the project's dedicated SSH release-signing key. If you already followed the project's `CONTRIBUTING.md` Setup B-iii section, you're done. Otherwise:

```bash
git config gpg.format ssh
git config tag.gpgSign true
git config user.signingkey <absolute path to your public key (.pub)>
git config gpg.ssh.allowedSignersFile .git/allowed_signers
```

And a one-line `.git/allowed_signers` file containing:

```
<your-email> <pasted contents of the .pub file>
```

The dedicated private key is local-only — it does not live in the repo. The public half is at `.github/release-signing-key.pub` and pinned in the "Trusted public signing key" section below.

---

## For users: verifying a release

### Path A: PyPI attestations (recommended for installable artifacts)

The official PyPI-native verification path uses `pypi-attestations`, a FLOSS CLI maintained by PyPA.

**Install:**

```bash
pip install pypi-attestations
```

**Verify** a wheel or sdist (replace `<version>` with the release you're checking):

```bash
# Against a local file
pip download --no-deps pic-standard==<version>
pypi-attestations verify pypi \
    --repository https://github.com/pic-standard/pic-standard \
    pic_standard-<version>-py3-none-any.whl

# Or against the PyPI URL directly (no local download)
pypi-attestations verify pypi \
    --repository https://github.com/pic-standard/pic-standard \
    https://files.pythonhosted.org/packages/.../pic_standard-<version>-py3-none-any.whl
```

**What the tool checks:**

- Fetches the attestation from PyPI
- Validates the Sigstore-issued certificate against the Trusted Publisher policy (workflow `release.yml` from `pic-standard/pic-standard`)
- Confirms the artifact bytes match the attestation's payload hash
- Cross-references the Sigstore transparency log

**Success output:** `OK!` (or equivalent verbose output indicating the attestation verified). **Failure output:** specific error indicating which check failed (signature mismatch, no attestation found, wrong publisher, etc.).

**Alternative (PyPI web UI):** PyPI exposes attestation/provenance information on the distribution file details view (https://pypi.org/project/pic-standard/). The CLI verification path above is the canonical, copy-pasteable check.

### Path B: Git tag signature

For users working with the source tree (cloning, auditing, building from source).

**One-time setup** — create a local allowed_signers file pinning the project's release-signing key:

```bash
# Make a directory for the policy file (choose any path you like).
mkdir -p ~/.config/git

# Write the trusted-signer entry. Format per Git's docs: one or more
# principals followed by the SSH public key. The key value below is the
# canonical public key for pic-standard releases (also pinned in
# .github/release-signing-key.pub in the repository).
cat > ~/.config/git/pic-allowed-signers <<'EOF'
fabio@madeinpluto.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDhoOQt2X+irvPwMj1zRuCAIhdH0kV3nKFiQzHLx/luS PIC Standard release signing key (madeinplutofabio)
EOF
```

**Verify a tag:**

```bash
git fetch origin --tags
git -c gpg.format=ssh \
    -c gpg.ssh.allowedSignersFile=~/.config/git/pic-allowed-signers \
    tag -v v<version>
```

**Success output:** `Good "git" signature for fabio@madeinpluto.com with ED25519 key SHA256:blCcqBpKLCrJUtUYwOvxE3tmUa4F37/COJvy8F80hHg`

**Failure output:** `error: no signature found` (tag is unsigned) or `Could not verify signature` (signed by a key not in your allowed_signers). Both should be treated as failed verification.

**Persistent setup** (if you verify pic-standard tags often): add the config lines to your global git config instead of using `git -c` inline:

```bash
git config --global gpg.ssh.allowedSignersFile ~/.config/git/pic-allowed-signers
git config --global gpg.format ssh   # WARNING: applies globally — see note
```

⚠️ Note: `gpg.format ssh` is repo-local in our project setup (per `CONTRIBUTING.md`), but if you set it globally it affects every repo that signs tags/commits. If you sign for another project using GPG, don't set this globally.

**Alternative (GitHub web UI):** GitHub shows tag verification status in the **Releases → Tags** view (https://github.com/pic-standard/pic-standard/tags). A "Verified" indicator on a tag reflects GitHub's server-side check against the maintainer's registered Signing Key, equivalent verification to running `git tag -v` locally.

---

## Trusted public signing key

**Algorithm:** Ed25519
**Format:** OpenSSH
**Status:** Active

### Public key (copy this entire line as one line)

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDhoOQt2X+irvPwMj1zRuCAIhdH0kV3nKFiQzHLx/luS PIC Standard release signing key (madeinplutofabio)
```

### SHA256 fingerprint (for out-of-band verification)

```
SHA256:blCcqBpKLCrJUtUYwOvxE3tmUa4F37/COJvy8F80hHg
```

### Where else this key appears

The same key value (with matching fingerprint) is published in three places. They MUST all agree:

1. **This document** (the section above)
2. **`.github/release-signing-key.pub`** in this repository — the file the release workflow reads to construct its runtime verification policy
3. **`madeinplutofabio`'s GitHub Signing Keys list** at https://github.com/settings/keys — what GitHub uses to display the "Verified" badge on signed tags

Out-of-band fingerprint verification: a user comparing the fingerprint from this file (read at a known git commit) against the fingerprint shown in their cloned tree provides defense-in-depth against in-transit tampering of the verification process itself.

---

## Troubleshooting

### `pypi-attestations verify pypi` fails with "no attestations found"

The artifact was uploaded **before** Trusted Publisher + PEP 740 attestations were wired up. Pre-`v<first signed version>` releases are **unsigned legacy artifacts** — they cannot be verified through this path. The first signed release with attestations is the first release whose tag triggered the `release.yml` workflow after PR-B merged.

### `git tag -v` fails with "error: no signature found"

The tag was created with `git tag -a` (annotated, unsigned) rather than `git tag -s` (annotated and signed). Pre-`v<first signed version>` tags are unsigned-legacy. Modern tags should always show a valid signature; if a recent tag is unsigned, either (a) the maintainer skipped signing (a process error — open an issue) or (b) the workflow's verify-signature step would have rejected it and you shouldn't see a corresponding GitHub Release in any case.

### `git tag -v` fails with "Could not verify signature"

The tag was signed by a key that's not in your `allowed_signers` file. Possible causes:

- You're using an outdated `allowed_signers` (the project rotated keys — see "Key rotation" below)
- The tag was signed by an unauthorized party (treat this as a security incident; open an issue)

Re-populate your `allowed_signers` with the current canonical line from this document, then retry.

### GitHub doesn't show the "Verified" badge but `git tag -v` locally succeeds

This can happen if the maintainer's GitHub Signing Key registration was removed, expired, or is otherwise out of sync with the publicly-pinned key. The local `git tag -v` is the authoritative check; GitHub's UI badge is a convenience layer. If they disagree, the local check (against the pinned key) is the source of truth.

### Workflow run fails at the "Verify tag signature" step

This is the workflow correctly rejecting an unsigned or wrongly-signed tag. The maintainer needs to:

1. Delete the unsigned/wrong-signed tag locally and remotely
2. Re-tag with `git tag -s`
3. Push the corrected tag

If a maintainer's local git config doesn't auto-sign tags, the workflow catches it here instead of in a downstream consumer surfacing an unverifiable release.

---

## Key rotation

If the dedicated SSH release-signing private key is compromised, lost, or otherwise needs replacement:

1. **Generate a new Ed25519 key** following the procedure in `CONTRIBUTING.md` Setup B-ii (use a different filename, e.g., `pic_standard_release_signing_v2`).
2. **Update `.github/release-signing-key.pub`** with the new public key contents.
3. **Update this `RELEASING.md`** — replace the "Trusted public signing key" section with the new key + fingerprint. Add a "Previous keys" subsection (if it doesn't exist) and append the old key with its retirement date for historical reference.
4. **Update `madeinplutofabio`'s GitHub Signing Keys list**: register the new key, then remove the old one.
5. **Update local git config** (`user.signingkey` path) to point at the new public key (`.pub`).
6. **Land the changes** as a single PR titled e.g., `chore: rotate release signing key (v2)`.
7. **Document the rotation event** in the PR description: when, why, and how downstream users should update their `allowed_signers`.

After rotation, the next tag signed with the new key will not be verifiable by users who haven't updated their `allowed_signers` file. The rotation event must be communicated (release notes, security advisory if applicable).

Old releases signed by the retired key remain verifiable if users retain the old key's entry in their `allowed_signers` policy. This document's "Previous keys" subsection serves as the canonical archive of retired keys.

---

## Notes on the OpenSSF Best Practices framing

The OpenSSF Best Practices `signed_releases` criterion was originally written assuming a **classic long-lived artifact-signing public-key model** ("documented process explaining to users how they can obtain the public signing keys and verify the signature(s)"). pic-standard's verification model is **two-layered and combines both modern and classic patterns**:

- **Layer 1 (PyPI artifacts):** modern Sigstore-issued ephemeral certificates per workflow run, anchored by GitHub Actions OIDC + Sigstore's transparency log. There is no long-lived artifact-signing public key for this layer — trust roots back to GitHub identity. This is the path PyPI's own consumer documentation publishes for verifying PEP 740 attestations.

- **Layer 2 (git tags):** classic long-lived public-key model. The Ed25519 signing key is published in-repo (`.github/release-signing-key.pub`), pinned in this document, and registered on GitHub. Verification uses the standard `git tag -v` + `allowed_signers` flow.

Both layers run for every release. The criterion's spirit — cryptographic verifiability + documented process + signing key not exclusively on the distribution site — is fully satisfied across both layers. A reviewer focused on "where is the public key?" can point at the Layer 2 SSH key. A reviewer focused on "modern attestation flow?" can point at the Layer 1 PyPI-attestations path.

If a reviewer asks for the project's long-lived public signing key, use the Layer 2 SSH tag-signing key (pinned above). Artifact verification itself is documented separately through the Layer 1 PyPI-attestations path — that path is identity-based and does not rely on a long-lived artifact-signing key.
