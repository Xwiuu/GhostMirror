"""Tests for the new interactive menu structure."""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from ghostmirror.app.cli import app
from ghostmirror.app.banner import render_banner, render_compact_banner


class TestBanner:
    def test_render_banner_runs(self, capsys):
        """Banner should render without errors."""
        render_banner()
        captured = capsys.readouterr()
        assert "GHOSTMIRROR" in captured.out

    def test_render_compact_banner_runs(self, capsys):
        """Compact banner should render without errors."""
        render_compact_banner()
        captured = capsys.readouterr()
        assert "GhostMirror" in captured.out


class TestMenu:
    def test_menu_exit(self, monkeypatch, tmp_path):
        """Menu should exit cleanly."""
        monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
        runner = CliRunner()
        result = runner.invoke(app, ["interactive"], input="0\n")
        assert result.exit_code == 0
        assert "Encerrando GhostMirror" in result.stdout

    def test_menu_create_project(self, monkeypatch, tmp_path):
        """Menu option 1 should create a project."""
        monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
        runner = CliRunner()
        input_seq = "1\nCliente Teste\nProjeto Teste\nteste.com\n\n0\n"
        result = runner.invoke(app, ["interactive"], input=input_seq)
        assert result.exit_code == 0
        assert "Projeto criado" in result.stdout

    def test_menu_system_doctor(self, monkeypatch, tmp_path):
        """Menu option 6 (Sistema) > 1 (Doctor) should work."""
        monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
        runner = CliRunner()
        with patch("ghostmirror.modules.platform.diagnostics.DependencyChecker.check_python_library", return_value=True):
            with patch("pathlib.Path.is_dir", return_value=True):
                result = runner.invoke(app, ["interactive"], input="6\n1\n\n0\n0\n")
                assert result.exit_code == 0
