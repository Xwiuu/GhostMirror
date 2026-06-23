# Contributing to GhostMirror

Thank you for your interest in contributing to GhostMirror. This document outlines the guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Branch Naming

Use the following convention for branch names:

- `feat/<description>` — new features
- `fix/<description>` — bug fixes
- `chore/<description>` — maintenance tasks
- `docs/<description>` — documentation updates
- `refactor/<description>` — code restructuring

## Commit Convention

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

Types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `security`

Examples:

- `feat(ssl): add TLS 1.3 support check`
- `fix(cli): handle empty project list gracefully`
- `chore(deps): update rust toolchain`
- `docs(api): document endpoint discovery workflow`

## Tests Required

All contributions must include or update tests:

```bash
# Python tests
pytest

# With coverage
pytest --cov=ghostmirror

# Rust tests
cd ghostmirror-rs
cargo test
cargo fmt --all --check
cargo clippy -- -D warnings
```

All tests must pass before merging. Coverage should not regress.

## Security Review Required

- All new modules and integrations must undergo security review.
- Do not introduce code that could be used for unauthorized access.
- Do not disable or weaken scope enforcement.
- Do not introduce unsafe deserialization or command injection risks.

## No Secrets

- **Never** commit secrets, API keys, tokens, passwords, or certificates.
- **Never** commit real client scan data, reports, or evidence.
- **Never** commit generated reports or scan outputs.
- Use environment variables or configuration files for sensitive values.

## No Generated Reports

- Do not commit files from `reports/`, `projects/`, or `logs/` directories.
- These directories are gitignored and should remain so.

## No Real Target Data

- All test data must use anonymized domains (`example.com`, `test.local`).
- Do not reference real client engagements in commit messages, PR descriptions, or comments.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## How to Open a PR

1. Ensure your branch is up to date with `main`.
2. Run all tests locally.
3. Open a PR against the `main` branch.
4. Describe what your change does and why.
5. Note any security impact.
6. Ensure no real client data appears in the PR description or comments.

## Code Style

- Python 3.12+ type annotations throughout.
- Follow existing patterns (`ScannerBase` subclassing, Pydantic models, etc.).
- One concern per module; keep CLI, core, and integration layers separate.
- Rust code must pass `cargo fmt` and `cargo clippy`.
