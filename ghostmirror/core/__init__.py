"""Core layer: use-case orchestration (project, scope, config, logging)."""

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.logger import get_logger, setup_logger
from ghostmirror.core.project_manager import (
    ProjectAlreadyExistsError,
    ProjectError,
    ProjectHandle,
    ProjectManager,
    ProjectNotFoundError,
)
from ghostmirror.core.scope_manager import ScopeManager

__all__ = [
    "ConfigManager",
    "ScopeManager",
    "ProjectManager",
    "ProjectHandle",
    "ProjectError",
    "ProjectAlreadyExistsError",
    "ProjectNotFoundError",
    "get_logger",
    "setup_logger",
]
