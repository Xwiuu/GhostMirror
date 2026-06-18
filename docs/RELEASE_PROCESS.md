# Release Process

## Versioning

GhostMirror uses `v<major>.<minor>-<stage>` format:

- `v1.0-alpha` — initial alpha
- `v1.0-beta` — beta pre-release
- `v1.0.0` — first stable

## Release Steps

1. **Update version** in `pyproject.toml` (`[project] version` field).
2. **Update CHANGELOG.md** with the new version entry.
3. **Run full test suite** and confirm 0 failures.
4. **Run `ghostmirror doctor`** and confirm READY status.
5. **Run `ghostmirror health-check`** and confirm HEALTHY.
6. **Build Docker image** and verify container starts:
   ```bash
   docker compose build
   docker compose run --rm ghostmirror version
   ```
7. **Commit** with message: `chore: release v<version>`.
8. **Tag** the release:
   ```bash
   git tag -a v<version> -m "GhostMirror v<version>"
   ```
9. **Push** tag:
   ```bash
   git push origin v<version>
   ```
10. **Create GitHub Release**:
    ```bash
    gh release create v<version> --title "GhostMirror v<version>" --notes-file RELEASE_NOTES.md
    ```

## Quality Gates

- All tests pass (pytest, 0 failures)
- Doctor reports READY
- Health-check reports HEALTHY
- Docker build succeeds
- No regression in coverage
