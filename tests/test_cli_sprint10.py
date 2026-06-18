"""Tests for Sprint 10 CLI additions: doctor, health-check, status, version."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from ghostmirror.app.cli import app
from ghostmirror.core.config_manager import ConfigManager

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "GhostMirror" in result.stdout
    assert "v1.0-alpha" in result.stdout
    assert "Build:" in result.stdout


def test_doctor_command():
    with patch("ghostmirror.modules.platform.diagnostics.DependencyChecker.check_python_library", return_value=True):
        with patch("pathlib.Path.is_dir", return_value=True):
            result = runner.invoke(app, ["doctor"])
            assert result.exit_code in (0, 1)
            assert "GhostMirror Doctor" in result.stdout or "Python" in result.stdout


def test_health_check_command():
    with patch("ghostmirror.modules.platform.diagnostics.DependencyChecker.check_python_library", return_value=True):
        with patch("pathlib.Path.is_dir", return_value=True):
            result = runner.invoke(app, ["health-check"])
            assert result.exit_code in (0, 1)
            assert "Nmap" in result.stdout or "Health Status" in result.stdout


def test_status_command_no_projects(home_dir: Path):
    with patch("ghostmirror.app.cli.bootstrap") as mock_boot:
        config = ConfigManager(base_dir=home_dir)
        config.load()
        from ghostmirror.core.scope_manager import ScopeManager
        from ghostmirror.core.project_manager import ProjectManager
        scopes = ScopeManager()
        projects = ProjectManager(config=config, scope_manager=scopes)
        mock_boot.return_value.config = config
        mock_boot.return_value.projects = projects
        mock_boot.return_value.scopes = scopes
        result = runner.invoke(app, ["status"])
        assert "Nenhum projeto encontrado" in result.stdout or result.exit_code == 0


def test_status_command_with_project(home_dir: Path):
    with patch("ghostmirror.app.cli.bootstrap") as mock_boot:
        config = ConfigManager(base_dir=home_dir)
        config.load()
        from ghostmirror.core.scope_manager import ScopeManager
        from ghostmirror.core.project_manager import ProjectManager
        scopes = ScopeManager()
        projects = ProjectManager(config=config, scope_manager=scopes)
        handle = projects.create_project(client="TestCorp", name="Status Test", domain="status-test.com")
        mock_boot.return_value.config = config
        mock_boot.return_value.projects = projects
        mock_boot.return_value.scopes = scopes
        result = runner.invoke(app, ["status", "--project", handle.slug])
        assert result.exit_code == 0
        assert "TestCorp" in result.stdout
        assert "status-test.com" in result.stdout
