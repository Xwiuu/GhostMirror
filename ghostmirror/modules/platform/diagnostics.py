"""Diagnostics aggregator for health check and doctor execution flows."""

from __future__ import annotations

from typing import Any

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.modules.platform.dependency_checker import DependencyChecker
from ghostmirror.modules.platform.environment import EnvironmentCollector
from ghostmirror.modules.platform.filesystem_validator import FilesystemValidator


class PlatformDiagnostics:
    """Consolidates system dependencies, directories, and configurations diagnostics."""

    def __init__(self, config: ConfigManager) -> None:
        self.config = config
        self.fs_validator = FilesystemValidator(config)

    def run_diagnostics(self) -> dict[str, Any]:
        """Runs a complete diagnostic check of the platform.

        Returns a dictionary containing structured checks status.
        """
        # 1. Environment Info
        env_info = EnvironmentCollector.get_runtime_info()

        # 2. Filesystem Checks
        fs_status = self.fs_validator.validate_platform_directories(repair=True)

        # 3. Binaries status
        binaries = ["nmap", "whatweb", "nuclei", "weasyprint", "docker"]
        binary_status = {
            binary: DependencyChecker.check_binary(binary) for binary in binaries
        }

        # 4. Docker daemon running
        docker_running = False
        if binary_status["docker"]:
            docker_running = DependencyChecker.check_docker_daemon()

        # 5. Libraries check
        pydantic_ok = DependencyChecker.check_python_library("pydantic")
        loguru_ok = DependencyChecker.check_python_library("loguru")
        ruamel_ok = DependencyChecker.check_python_library("ruamel.yaml") or DependencyChecker.check_python_library("yaml")
        weasyprint_lib_ok = DependencyChecker.check_python_library("weasyprint")

        # 6. Lab catalog checks
        lab_catalog_ok = False
        lab_compose_files_ok = False
        try:
            from ghostmirror.modules.lab import LabCatalog

            lab_errors = LabCatalog.validate_catalog()
            lab_catalog_ok = len(lab_errors) == 0
            lab_compose_checks = LabCatalog.compose_files_exist()
            lab_compose_files_ok = all(lab_compose_checks.values())
        except Exception:
            pass

        return {
            "environment": env_info,
            "filesystem": fs_status,
            "binaries": binary_status,
            "docker_daemon_running": docker_running,
            "libraries": {
                "pydantic": pydantic_ok,
                "loguru": loguru_ok,
                "yaml": ruamel_ok,
                "weasyprint": weasyprint_lib_ok,
            },
            "lab": {
                "catalog_valid": lab_catalog_ok,
                "compose_files_present": lab_compose_files_ok,
            },
        }
