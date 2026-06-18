"""Engagement scope management (``scope.yaml``)."""

from __future__ import annotations

from pathlib import Path

from ghostmirror.core.logger import get_logger
from ghostmirror.models.scope import (
    AllowedTests,
    ScopeModel,
    ScopeProjectInfo,
    ScopeTargets,
)
from ghostmirror.storage.filesystem import FileSystemStorage

logger = get_logger()


class ScopeManager:
    """Builds, persists and validates scope definitions.

    Decoupled from project lifecycle so that scope handling can be reused by
    future modules (scanners, validators, report generators).
    """

    SCOPE_FILENAME = "scope.yaml"

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    def build_default_scope(
        self,
        *,
        client: str,
        name: str,
        domain: str | None = None,
    ) -> ScopeModel:
        """Create a conservative default scope for a new project."""

        domains = [domain] if domain else []
        return ScopeModel(
            project=ScopeProjectInfo(client=client, name=name),
            targets=ScopeTargets(domains=domains, ips=[]),
            allowed_tests=AllowedTests(),
        )

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def write_scope(self, scope_path: Path, scope: ScopeModel) -> Path:
        FileSystemStorage.write_yaml(scope_path, scope.model_dump())
        logger.info("SCOPE_WRITTEN path={}", scope_path)
        return scope_path

    def load_scope(self, scope_path: Path) -> ScopeModel:
        """Read and validate a scope file. Raises on any problem."""

        if not scope_path.exists():
            raise FileNotFoundError(f"Scope file not found: {scope_path}")
        raw = FileSystemStorage.read_yaml(scope_path)
        scope = ScopeModel.model_validate(raw)
        logger.info(
            "SCOPE_LOADED path={} domains={} ips={}",
            scope_path,
            len(scope.targets.domains),
            len(scope.targets.ips),
        )
        return scope

    def validate_scope(self, scope_path: Path) -> tuple[bool, str | None]:
        """Validate a scope file without raising.

        Returns ``(True, None)`` when valid, otherwise ``(False, reason)``.
        """

        try:
            self.load_scope(scope_path)
        except Exception as exc:  # noqa: BLE001 - we report any failure reason
            logger.error("SCOPE_INVALID path={} error={}", scope_path, exc)
            return False, str(exc)
        return True, None

    def is_ready_for_testing(self, scope: ScopeModel) -> bool:
        """Whether a (structurally valid) scope defines any target to test.

        Future scanner modules must gate on this before acting on a scope.
        """

        return scope.has_targets
