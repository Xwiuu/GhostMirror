# Contributing

GhostMirror is an internal tool. External contributions are not expected.

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Code Style

- Python 3.12+ type annotations throughout
- Follow existing patterns (`ScannerBase` subclassing, Pydantic models, etc.)
- One concern per module; keep CLI, core, and integration layers separate

## Testing

```bash
pytest                    # all tests
pytest --cov=ghostmirror  # with coverage
```

All tests must pass before merging. Coverage should not regress.

## Commit Messages

Conventional Commits format: `type: description`

- `feat:` — new feature
- `fix:` — bug fix
- `chore:` — maintenance
- `docs:` — documentation
- `test:` — testing
- `refactor:` — code restructuring

## Pull Requests

- PRs should target the `main` branch.
- Include a description of what and why.
- Ensure all CI checks pass.
- No real client data in PR descriptions or comments.
