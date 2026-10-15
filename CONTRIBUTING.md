# Contributing

Thanks for your interest. This tool verifies a live service, which makes a few things unusual. Please skim this before opening a PR.

## Found a security issue?

Don't open a public issue. See [SECURITY.md](SECURITY.md). It explains which of the three possible targets (this verifier, Brave's deployment, or NEAR's services) your finding belongs to.

## Getting set up

```bash
make install
poetry run pre-commit install   # required, not optional
cp .env.example .env.local      # then add your NEAR API key
```

The base branch is **`master`**, not `main`.

## Before you open a PR

```bash
make test       # unit tests (offline, no credentials needed; needs Docker Compose 5.1.4, see README)
make check      # mypy, bandit, vulture
make lint       # shell syntax + ruff
```

CI runs the tests on Python 3.11 through 3.14, and lint, the format check, mypy, bandit and vulture on 3.11 (the deployment runtime).

Two things that bite people:

- **Python 3.11 is the deployment runtime** (AWS CodeBuild). An f-string whose expression spans multiple lines is valid 3.12+ syntax and a **syntax error on 3.11**. `ruff`'s `target-version = "py311"` guards it; don't change that setting.
- **Pre-commit hook versions must match the dev dependencies in `pyproject.toml`.** If they drift, pre-commit passes code that CI rejects. Bump both together. The mypy hook runs without the project's runtime dependencies, so `make check` is the authoritative type check.

## Tests

A verification check is only real if a test proves it *fails* when it should. A check that always reports success passes every happy-path test. If you touch verification logic, add a test asserting the fail-closed direction. See `tests/test_soundness_invariants.py` for the pattern.

There is a coverage floor (`--cov-fail-under` in `pyproject.toml`). Raise it if you improve coverage; don't lower it to make a change fit.

## What's maintainer-only

**Pin bumps (`make review-pins`).** The pins in `verifier/config.py` are the audited commits the live deployment is checked against. Updating them requires reviewing each upstream diff, and the workflow pushes release branches and triggers Brave's CodeBuild. Please don't send pin-bump PRs. If you notice the pins are stale, open an issue instead.

The same goes for anything under the AWS CodeBuild path; it needs Brave credentials and can't be exercised from a fork.

## Scope

This verifier deliberately trusts a small set of roots (Intel, NVIDIA, Sigstore, the audited upstream repos) and states so in the README's trust assumptions. Changes that widen what the tool accepts need a clear argument in the PR description for why the weaker check is still sound.
