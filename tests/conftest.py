"""Shared pytest fixtures for the GhostMirror test-suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.logger import setup_logger
from ghostmirror.core.project_manager import ProjectManager
from ghostmirror.core.scope_manager import ScopeManager


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    """An isolated GhostMirror home directory backed by a temp folder."""

    (tmp_path / "config").mkdir()
    return tmp_path


@pytest.fixture()
def config(home_dir: Path) -> ConfigManager:
    manager = ConfigManager(base_dir=home_dir)
    manager.load()
    # Route logs into the temp home so tests never touch the real log file.
    setup_logger(manager.logs_dir)
    return manager


@pytest.fixture()
def scope_manager() -> ScopeManager:
    return ScopeManager()


@pytest.fixture()
def project_manager(config: ConfigManager, scope_manager: ScopeManager) -> ProjectManager:
    return ProjectManager(config=config, scope_manager=scope_manager)
