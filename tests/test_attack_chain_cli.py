from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from ghostmirror.app.cli import app
from ghostmirror.models.attack_chain_report import AttackChainReport


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def mock_app_context():
    with patch("ghostmirror.app.cli.bootstrap") as mock:
        ctx = MagicMock()
        ctx.config.base_dir = Path("/tmp")
        ctx.config.projects_dir = Path("/tmp/projects")
        ctx.config.logs_dir = Path("/tmp/logs")
        ctx.config.reports_dir = Path("/tmp/reports")
        mock.return_value = ctx
        yield mock


class TestAttackChainCLI:
    def test_attack_chain_help(self, runner: CliRunner):
        result = runner.invoke(app, ["attack-chain", "--help"])
        assert result.exit_code == 0
        assert "Attack Chain Intelligence" in result.output

    def test_attack_chain_run_help(self, runner: CliRunner):
        result = runner.invoke(app, ["attack-chain", "run", "--help"])
        assert result.exit_code == 0

    def test_attack_chain_graph_help(self, runner: CliRunner):
        result = runner.invoke(app, ["attack-chain", "graph", "--help"])
        assert result.exit_code == 0

    def test_attack_chain_top_help(self, runner: CliRunner):
        result = runner.invoke(app, ["attack-chain", "top", "--help"])
        assert result.exit_code == 0

    def test_attack_chain_report_help(self, runner: CliRunner):
        result = runner.invoke(app, ["attack-chain", "report", "--help"])
        assert result.exit_code == 0

    def test_analyze_attack_chain_help(self, runner: CliRunner):
        result = runner.invoke(app, ["analyze", "attack-chain", "--help"])
        assert result.exit_code == 0

    def test_attack_chain_run_no_project(self, runner: CliRunner):
        with patch("ghostmirror.app.cli.bootstrap") as mock_bootstrap:
            ctx = MagicMock()
            ctx.projects.list_projects.return_value = []
            mock_bootstrap.return_value = ctx
            result = runner.invoke(app, ["attack-chain", "run"])
            assert result.exit_code == 1

    def test_attack_chain_graph_no_project(self, runner: CliRunner):
        with patch("ghostmirror.app.cli.bootstrap") as mock_bootstrap:
            ctx = MagicMock()
            ctx.projects.list_projects.return_value = []
            mock_bootstrap.return_value = ctx
            result = runner.invoke(app, ["attack-chain", "graph"])
            assert result.exit_code == 1

    def test_attack_chain_report_no_data(self, runner: CliRunner, tmp_path: Path):
        with patch("ghostmirror.app.cli.bootstrap") as mock_bootstrap:
            ctx = MagicMock()
            handle = MagicMock()
            handle.path = tmp_path
            handle.metadata.domain = "test.com"
            ctx.projects.list_projects.return_value = [handle]
            ctx.projects.open_project.return_value = handle
            mock_bootstrap.return_value = ctx
            result = runner.invoke(app, ["attack-chain", "report", "--project", "test"])
            assert result.exit_code == 1
            assert "Attack chain report not found" in result.output

    def test_attack_chain_top_no_data(self, runner: CliRunner, tmp_path: Path):
        with patch("ghostmirror.app.cli.bootstrap") as mock_bootstrap:
            ctx = MagicMock()
            handle = MagicMock()
            handle.path = tmp_path
            ctx.projects.list_projects.return_value = [handle]
            ctx.projects.open_project.return_value = handle
            mock_bootstrap.return_value = ctx
            result = runner.invoke(app, ["attack-chain", "top", "--project", "test"])
            assert result.exit_code == 1
            assert "Attack chain data not found" in result.output
