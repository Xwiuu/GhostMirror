from __future__ import annotations

from pathlib import Path

import pytest

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.modules.platform.filesystem_validator import FilesystemValidator


@pytest.fixture()
def validator(home_dir: Path) -> FilesystemValidator:
    config = ConfigManager(base_dir=home_dir)
    config.load()
    return FilesystemValidator(config)


class TestFilesystemValidator:
    def test_validate_platform_dirs_repair(self, validator: FilesystemValidator, home_dir: Path):
        status = validator.validate_platform_directories(repair=True)
        assert isinstance(status, dict)
        for key in ("projects", "logs", "reports"):
            assert key in status
            assert status[key] is True
            assert (validator.config.base_dir / key).is_dir()

    def test_validate_platform_dirs_no_repair(self, validator: FilesystemValidator, home_dir: Path):
        missing = home_dir / "projects_missing"
        validator.config._settings.paths.projects = "projects_missing"
        status = validator.validate_platform_directories(repair=False)
        assert "projects" not in status or status.get("projects") is False

    def test_validate_project_dirs_repair(self, validator: FilesystemValidator, tmp_path: Path):
        proj_path = tmp_path / "test-project"
        proj_path.mkdir()
        status = validator.validate_project_directories(proj_path, repair=True)
        assert status["root"] is True
        for subdir in FilesystemValidator.PROJECT_LEVEL_SUBDIRS:
            assert status[subdir] is True
            assert (proj_path / subdir).is_dir()

    def test_validate_project_dirs_missing_root(self, validator: FilesystemValidator, tmp_path: Path):
        status = validator.validate_project_directories(tmp_path / "nonexistent", repair=True)
        assert status["root"] is False

    def test_validate_project_dirs_no_repair(self, validator: FilesystemValidator, tmp_path: Path):
        proj_path = tmp_path / "test-project"
        proj_path.mkdir()
        status = validator.validate_project_directories(proj_path, repair=False)
        assert status["root"] is True
        for subdir in FilesystemValidator.PROJECT_LEVEL_SUBDIRS:
            assert status.get(subdir) is False

    def test_project_level_subdirs_defined(self):
        expected = {"logs", "findings", "evidence", "reports", "profiles", "execution", "recommendations"}
        assert set(FilesystemValidator.PROJECT_LEVEL_SUBDIRS) == expected
