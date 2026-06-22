# PIC Conformance Suite
Executable conformance vectors that pin the PIC verifier's behaviour. Every vector is
listed in [`manifest.json`](manifest.json) and run by [`run.py`](run.py). The suite is
the cross-implementation contract: a second-language verifier is conformant when it
passes every vector here.
**New contributor?** Start with [Adding a conformance vector](adding-a-vector.md).
## Run the suite
```bash
pip install -e "./sdk-python"                  # once, from the repo root
python -m conformance.run                      # all vectors
python -m conformance.run --filter-mode core   # one mode
python -m conformance.run --filter-id <id> -v  # one vector, verbose
python -m conformance.run --json               # machine-readable output
```
Exit code `0` means all selected vectors passed, `1` means a vector failed, and
`2` means the manifest is malformed or the filter selected nothing.
## Modes
| Mode                 | Directory                                             | What it checks                        |
| -------------------- | ----------------------------------------------------- | ------------------------------------- |
| `core`               | [`core/`](core/README.md)                             | allow/block decisions of the verifier |
| `canonicalization`   | [`canonicalization/`](canonicalization/README.md)     | byte-exact JSON canonical form        |
| `evidence`           | [`evidence/`](evidence/README.md)                     | hash/signature evidence verification  |
| `trust_sanitization` | [`trust_sanitization/`](trust_sanitization/README.md) | `strict_trust` behaviour              |
Each mode directory has its own README with the exact vector file format and rules.
The conformance suite runs on every PR via the `Conformance vectors` CI check.
