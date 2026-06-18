"""Unit tests for the Sprint 9 interactive CLI menus and subcommands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from ghostmirror.app.cli import app


def test_cli_full_scan_missing_project(monkeypatch, tmp_path: Path):
    """Command must fail with non-zero exit code if project is missing."""
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["full-scan", "--project", "non-existent", "--profile", "lite"])
    assert result.exit_code == 1
    assert "Erro ao abrir o projeto" in result.stdout


@patch("ghostmirror.modules.orchestrator.full_scan.FullScanOrchestrator.run")
def test_cli_full_scan_success(mock_orchestrator_run, monkeypatch, tmp_path: Path):
    """Command must call FullScanOrchestrator and return successfully."""
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()

    # Create dummy project
    runner.invoke(app, ["create", "-c", "Acme", "-n", "Pentest", "-d", "acme.com"])

    # Mock orchestrator run response
    mock_orchestrator_run.return_value = {
        "project": "acme-pentest",
        "target": "acme.com",
        "profile": "standard",
        "steps": [
            {"name": "headers", "status": "completed", "duration": 1.5, "findings": 2},
            {"name": "ssl", "status": "completed", "duration": 0.8, "findings": 0},
            {"name": "report", "status": "completed", "duration": 0.2, "findings": 0},
        ]
    }

    result = runner.invoke(app, ["full-scan", "--project", "acme-pentest", "--profile", "standard"])
    assert result.exit_code == 0
    assert "Full Scan (STANDARD) concluído com sucesso!" in result.stdout
    assert "- headers: completed" in result.stdout
    assert "- ssl: completed" in result.stdout


def test_cli_report_missing_project(monkeypatch, tmp_path: Path):
    """Report command must fail if project slug doesn't resolve."""
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["report", "generate", "--project", "non-existent", "--format", "html"])
    assert result.exit_code == 1
    assert "Erro ao abrir o projeto" in result.stdout


@patch("ghostmirror.modules.reporting.generator.ReportGenerator.generate")
def test_cli_report_success(mock_generate, monkeypatch, tmp_path: Path):
    """Report command must call ReportGenerator and exit successfully."""
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()

    runner.invoke(app, ["create", "-c", "Acme", "-n", "Pentest", "-d", "acme.com"])

    mock_generate.return_value = {
        "score": 45,
        "risk_level": "HIGH",
        "generated_files": ["reports/report.html"],
    }

    result = runner.invoke(app, ["report", "generate", "--project", "acme-pentest", "--format", "html"])
    assert result.exit_code == 0
    assert "Relatório (HTML) gerado com sucesso!" in result.stdout
    assert "Risco Global Mapeado: HIGH (Score: 45)" in result.stdout


def test_cli_interactive_menu_exit(monkeypatch, tmp_path: Path):
    """Interactive menu should exit cleanly with input 0."""
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()

    # Input '0' to exit from main menu
    result = runner.invoke(app, ["interactive"], input="0\n")
    assert result.exit_code == 0
    assert "Encerrando GhostMirror. Até logo!" in result.stdout


def test_cli_interactive_system_doctor(monkeypatch, tmp_path: Path):
    """Interactive menu should support system > doctor navigation."""
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()

    # Sistema [6] -> Doctor [1] -> back [0] -> exit [0]
    with patch("ghostmirror.modules.platform.diagnostics.DependencyChecker.check_python_library", return_value=True):
        with patch("pathlib.Path.is_dir", return_value=True):
            result = runner.invoke(app, ["interactive"], input="6\n1\n\n0\n0\n")
            assert result.exit_code == 0
            assert "GhostMirror Doctor" in result.stdout or "Encerrando GhostMirror" in result.stdout
