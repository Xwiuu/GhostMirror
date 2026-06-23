## Description

Describe the change and why it is needed.

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Refactor / Chore
- [ ] Security fix
- [ ] Test update

## Authorized Use Confirmation

- [ ] I confirm this PR does **not** contain real client data, scan outputs, reports, or confidential information.
- [ ] I confirm all test data is anonymized (e.g., `example.com`, `test.local`).

## Tests Run

- [ ] `pytest` — all tests pass
- [ ] `pytest --cov=ghostmirror` — coverage does not regress
- [ ] `cd ghostmirror-rs && cargo test`
- [ ] `cd ghostmirror-rs && cargo fmt --all --check`
- [ ] `cd ghostmirror-rs && cargo clippy -- -D warnings`

## Security Impact

- [ ] No security impact
- [ ] Security review required (describe below)

## Related Issues

Closes #...

## Checklist

- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have added tests that prove my fix/feature works
- [ ] No new secrets, credentials, or tokens are introduced
- [ ] No generated reports or scan outputs are committed
