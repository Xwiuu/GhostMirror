"""Filesystem structures validation and automatic folder directory repair."""

from __future__ import annotations

from pathlib import Path

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.logger import get_logger

logger = get_logger()


class FilesystemValidator:
    """Checks that directories are structured correctly on disk, repairing them as needed."""

    PROJECT_LEVEL_SUBDIRS = (
        "logs",
        "findings",
        "evidence",
        "reports",
        "profiles",
        "execution",
        "recommendations",
    )

    def __init__(self, config: ConfigManager) -> None:
        self.config = config

    def validate_platform_directories(self, repair: bool = True) -> dict[str, bool]:
        """Validate and repair top-level directories (projects, logs, reports)."""
        dirs = {
            "projects": self.config.projects_dir,
            "logs": self.config.logs_dir,
            "reports": self.config.reports_dir,
        }
        status = {}

        for name, path in dirs.items():
            exists = path.is_dir()
            if not exists and repair:
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    logger.info("DIR_REPAIRED path={}", path)
                    exists = True
                except Exception as exc:
                    logger.error("DIR_REPAIR_FAILED path={} error={}", path, exc)
            status[name] = exists

        return status

    def validate_project_directories(self, project_path: Path, repair: bool = True) -> dict[str, bool]:
        """Validate and repair project-specific directories."""
        status = {}
        project_path = Path(project_path).resolve()

        if not project_path.is_dir():
            status["root"] = False
            return status

        status["root"] = True
        for subdir in self.PROJECT_LEVEL_SUBDIRS:
            sub_path = project_path / subdir
            exists = sub_path.is_dir()
            if not exists and repair:
                try:
                    sub_path.mkdir(parents=True, exist_ok=True)
                    logger.info("PROJECT_DIR_REPAIRED path={}", sub_path)
                    exists = True
                except Exception as exc:
                    logger.error("PROJECT_DIR_REPAIR_FAILED path={} error={}", sub_path, exc)
            status[subdir] = exists

        return status
