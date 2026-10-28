# Developer Setup Guide

This guide walks a newcomer from a clean clone to a passing test suite and two verifications (one accepted, one rejected), then shows how to start a contribution branch.

Validated at `v0.9.0` (commit `f745b1cd`) with Python 3.10.21 on Linux. The sequence also worked for the maintainer on Windows with Python 3.11.9. `pyproject.toml` declares `requires-python = ">=3.10"`.

## Prerequisites

- Git
- Python `>=3.10`

## Clone and create a virtual environment

```bash
git clone https://github.com/pic-standard/pic-standard.git
cd pic-standard
git checkout v0.9.0
python -m venv .venv
```

Activate the environment:

- Linux / macOS:
  ```bash
  source .venv/bin/activate
  ```
- Windows (Git Bash):
  ```bash
  source .venv/Scripts/activate
  ```
- Windows (Command Prompt / PowerShell):
  ```bash
  .venv\Scripts\activate
  ```

## Install dependencies and the package

```bash
python -m pip install \
  -r sdk-python/requirements.txt \
  -r sdk-python/requirements-dev.txt \
  -r sdk-python/requirements-langgraph.txt \
  -r sdk-python/requirements-mcp.txt
python -m pip install -e ".[crypto]"
```

These requirement files match the pinned dependency job in `.github/workflows/ci.yml` at `v0.9.0`. `requirements-dev.txt` provides pytest, ruff, coverage and PyYAML; the langgraph and mcp files are needed for the integration tests.

## Run the test suite

```bash
python -m pytest -q
```

Recorded baseline at `v0.9.0`:

```text
324 passed
```

## Two quick verifications

```bash
pic-cli verify examples/read_only_query.json         # exit 0, accepted
pic-cli verify examples/financial_irreversible.json  # exit 3, rejected
```

For explanations of why these results occur, see the walkthroughs:

- [Why a read-only proposal is allowed with untrusted provenance](https://github.com/pic-standard/pic-standard/issues/175)
- [Why a payment proposal is blocked](https://github.com/pic-standard/pic-standard/issues/174)

## Starting a contribution

Create a branch from current `main` (not from a release tag):

```bash
git switch -c docs/your-feature origin/main
```

Sign off commits with `git commit -s` and open the pull request against `main`. See [CONTRIBUTING.md](../CONTRIBUTING.md) for DCO details.

> The installation and test results above apply to `v0.9.0`. After creating your contribution branch from current `main`, follow that branch's dependency and validation instructions. The editable installation uses the checked-out source, but installed dependencies are not automatically updated when switching branches.

Keep troubleshooting explanations in the [troubleshooting guide](https://github.com/pic-standard/pic-standard/issues/178). See also the [README](../README.md) for a project overview.
