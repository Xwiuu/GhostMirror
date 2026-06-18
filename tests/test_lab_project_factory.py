"""Tests for the lab project factory module."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.exceptions import ProjectAlreadyExistsError
from ghostmirror.core.project_manager import ProjectManager
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.lab.catalog import LabCatalog
from ghostmirror.modules.lab.project_factory import LabProjectFactory, LAB_CLIENT, PROJECT_SUBDIRS
from ghostmirror.storage.filesystem import FileSystemStorage


@pytest.fixture()
def home_dir(tmp_path: Path) -> Path:
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    return tmp_path


@pytest.fixture()
def config(home_dir: Path) -> ConfigManager:
    manager = ConfigManager(base_dir=home_dir)
    manager.load()
    return manager


@pytest.fixture()
def factory(config: ConfigManager) -> LabProjectFactory:
    return LabProjectFactory(config=config)


class TestLabProjectFactory:
    def test_create_project_for_juice_shop(self, factory: LabProjectFactory) -> None:
        lab = LabCatalog.get("juice-shop")
        handle = factory.create(lab)

        assert handle.slug == "lab-juice-shop"
        assert handle.path.exists()
        assert handle.metadata.client == LAB_CLIENT
        assert "Juice Shop" in handle.metadata.name

    def test_create_project_directory_structure(self, factory: LabProjectFactory) -> None:
        lab = LabCatalog.get("dvwa")
        handle = factory.create(lab)

        for subdir in PROJECT_SUBDIRS:
            assert (handle.path / subdir).is_dir(), f"Missing subdir: {subdir}"
        assert (handle.path / "metadata.json").exists()
        assert (handle.path / "scope.yaml").exists()

    def test_create_project_scope(self, factory: LabProjectFactory) -> None:
        lab = LabCatalog.get("webgoat")
        handle = factory.create(lab)

        scope_manager = ScopeManager()
        scope = scope_manager.load_scope(handle.path / "scope.yaml")

        assert scope.project.lab is True
        assert scope.project.client == LAB_CLIENT
        assert "127.0.0.1" in scope.targets.ips
        assert lab.default_url in scope.targets.urls
        assert scope.allowed_tests.destructive_tests is False
        assert scope.allowed_tests.web_scan is True

    def test_create_project_twice_raises(self, factory: LabProjectFactory) -> None:
        lab = LabCatalog.get("juice-shop")
        factory.create(lab)

        with pytest.raises(ProjectAlreadyExistsError):
            factory.create(lab)

    def test_create_project_for_vuln_demo(self, factory: LabProjectFactory) -> None:
        lab = LabCatalog.get("vuln-demo")
        handle = factory.create(lab)

        assert handle.slug == "lab-vuln-demo"
        scope_manager = ScopeManager()
        scope = scope_manager.load_scope(handle.path / "scope.yaml")
        assert scope.project.lab is True
        assert "http://localhost:8000" in scope.targets.urls

    def test_find_lab_project_exists(self, factory: LabProjectFactory, config: ConfigManager) -> None:
        lab = LabCatalog.get("juice-shop")
        factory.create(lab)

        found = LabProjectFactory.find_lab_project(config.projects_dir, "juice-shop")
        assert found is not None
        assert found.name == "lab-juice-shop"

    def test_find_lab_project_not_exists(self, config: ConfigManager) -> None:
        found = LabProjectFactory.find_lab_project(config.projects_dir, "nonexistent")
        assert found is None

    def test_project_metadata_has_lab_notes(self, factory: LabProjectFactory) -> None:
        lab = LabCatalog.get("juice-shop")
        handle = factory.create(lab)

        metadata = FileSystemStorage.read_json(handle.path / "metadata.json")
        assert "Lab Mode" in metadata.get("notes", "")
        assert "Auto-generated" in metadata.get("notes", "")
