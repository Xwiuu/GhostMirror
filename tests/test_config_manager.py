"""Tests for the configuration manager."""

from __future__ import annotations

from pathlib import Path

from ghostmirror.core.config_manager import ConfigManager


def test_load_creates_default_settings(home_dir: Path) -> None:
    # Remove the pre-created config dir to exercise first-run creation.
    config_file = home_dir / "config" / "settings.yaml"
    assert not config_file.exists()

    manager = ConfigManager(base_dir=home_dir)
    settings = manager.load()

    assert config_file.exists()
    assert settings.app.name == "GhostMirror"


def test_resolves_paths_against_base_dir(home_dir: Path) -> None:
    manager = ConfigManager(base_dir=home_dir)
    manager.load()

    assert manager.projects_dir == (home_dir / "projects").resolve()
    assert manager.logs_dir == (home_dir / "logs").resolve()
    assert manager.reports_dir == (home_dir / "reports").resolve()


def test_reloads_existing_settings(home_dir: Path) -> None:
    ConfigManager(base_dir=home_dir).load()  # writes defaults
    # A second manager should read, not overwrite.
    manager = ConfigManager(base_dir=home_dir)
    settings = manager.load()
    assert settings.app.version == "1.0-alpha"
