# Conformance artifacts

Portable byte-stable files referenced by hash-evidence conformance vectors under
[`conformance/evidence/`](../evidence/).

## Contract

Files in this directory are part of the **portable conformance surface**:

1. **Byte-stable.** SHA-256 of each file MUST be reproducible across `git clone`
   invocations on Linux, macOS, and Windows. This is enforced by the repo-root
   [`.gitattributes`](../../.gitattributes) entry:

   ```
   conformance/artifacts/*.txt text eol=lf
   ```

   That entry forces LF on checkout regardless of platform or `core.autocrlf`,
   so Windows clones produce the same file bytes as POSIX clones.

2. **SHA-pinned by vectors.** Each artifact is referenced by an evidence vector
   under `conformance/evidence/<allow|block>/*.json` via:

   ```json
   {
     "evidence": [{
       "id": "...",
       "type": "hash",
       "ref": "file://invoice_001.txt",
       "sha256": "a2e818612ae44f799be83833149cdd8a1ea750fa8d40bc8507f874f8ad488fbd"
     }]
   }
   ```

   The `ref` is resolved relative to the vector's declared `evidence_root_dir`
   (which itself is resolved relative to the **repository root** — see
   [`conformance/evidence/README.md`](../evidence/README.md) for the full
   path-resolution rule).

3. **Committed, not generated.** Files MUST be present in the repository (this
   directory) as literal bytes. The conformance runner MUST NOT regenerate
   them at test time, because that would defeat byte-stability — generation
   semantics drift across language implementations.

## Files

| File | SHA-256 | Description |
|------|---------|-------------|
| `invoice_001.txt` | `a2e818612ae44f799be83833149cdd8a1ea750fa8d40bc8507f874f8ad488fbd` | Sample vendor invoice (102 bytes, ASCII, LF) — referenced by `evidence-hash-allow-001-simple` and other hash-evidence vectors. |
| `cfo_approval_001.txt` | `cfbe63b0ea76039a33f7e81091bf9eaa3cc9d2f9cb9c096e9837aef79e96a98d` | Sample CFO approval note (132 bytes, ASCII, LF) — referenced by `evidence-hash-allow-002-multiple-hashes` and `evidence-mixed-allow-001-hash-and-sig`. |

## Adding a new artifact

When adding an artifact:

1. Create the file under `conformance/artifacts/`. Use the existing
   filename convention (`<kind>_<sequence>.<ext>`, e.g., `invoice_002.txt`,
   `cfo_approval_001.txt`).

2. Verify byte-stability locally:

   ```bash
   python -c "import hashlib; print(hashlib.sha256(open('conformance/artifacts/<name>','rb').read()).hexdigest())"
   ```

3. Pin that SHA-256 into the matching evidence vector(s) under
   `conformance/evidence/`.

4. Add a row to the **Files** table above.

5. If the artifact uses an extension other than `.txt`, extend the
   `.gitattributes` pattern to include it under the same `text eol=lf`
   constraint (or `binary` if the file is genuinely binary).

## Why not just generate hashes at runtime?

Two reasons:

- **Cross-language parity.** Hash semantics must be identical in the Python
  reference runner and the future TypeScript verifier. Committing the bytes
  and the SHA forces both implementations to read the same file bytes and
  reach the same SHA-256 — there's no "what does this language's file-read
  helper do with newlines?" failure mode.

- **Reviewable signal.** A reviewer reading a vector PR sees the artifact
  bytes and the pinned hash side-by-side and can verify the binding manually.
  A runtime-generated hash hides that signal.
