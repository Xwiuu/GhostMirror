"""Validator for target projects, scopes (scope.yaml), metadata and target setups."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.exceptions import (
    InvalidConfigurationError,
    ProjectNotFoundError,
    ScopeViolationError,
)
from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager

logger = get_logger()


class ProjectValidator:
    """Performs validation checks against concrete projects, metadata files, and scope definitions."""

    def __init__(self, scope_manager: ScopeManager | None = None) -> None:
        self.scope_manager = scope_manager or ScopeManager()

    def validate_project(self, project_path: Path | str) -> dict[str, Any]:
        """Runs a validation scan over a project path, returning structural correctness status.

        Raises exceptions if critical structures are corrupted or missing.
        """
        path = Path(project_path).resolve()
        report: dict[str, Any] = {
            "exists": False,
            "metadata_exists": False,
            "scope_exists": False,
            "scope_valid": False,
            "targets_defined": False,
            "errors": [],
        }

        if not path.is_dir():
            err_msg = f"Diretório do projeto não encontrado: {path}"
            report["errors"].append(err_msg)
            logger.error("PROJECT_VALIDATION_FAILED error={}", err_msg)
            raise ProjectNotFoundError(err_msg)

        report["exists"] = True

        # Check metadata.json
        meta_path = path / "metadata.json"
        if not meta_path.exists():
            report["errors"].append("metadata.json não encontrado.")
        else:
            report["metadata_exists"] = True
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    json.load(f)
            except Exception as exc:
                report["errors"].append(f"metadata.json corrompido: {exc}")

        # Check scope.yaml
        scope_path = path / "scope.yaml"
        if not scope_path.exists():
            err_msg = "Arquivo de escopo scope.yaml não encontrado."
            report["errors"].append(err_msg)
            logger.error("PROJECT_VALIDATION_FAILED error={}", err_msg)
            raise ScopeViolationError(err_msg)

        report["scope_exists"] = True

        try:
            scope = self.scope_manager.load_scope(scope_path)
            valid, reason = self.scope_manager.validate_scope(scope_path)
            if not valid:
                report["errors"].append(f"scope.yaml inválido: {reason}")
            else:
                report["scope_valid"] = True

            # Check if testing targets are ready
            ready = self.scope_manager.is_ready_for_testing(scope)
            if not ready:
                report["errors"].append("Nenhum alvo (domínio ou IP) definido no escopo.")
            else:
                report["targets_defined"] = True
                
        except Exception as exc:
            report["errors"].append(f"Erro ao carregar o escopo: {exc}")

        if report["errors"] and not report["scope_valid"]:
            # If critical errors in scope validation, we might want to flag it
            logger.warning("PROJECT_VALIDATION_WARNINGS path={} errors={}", path, report["errors"])

        return report
