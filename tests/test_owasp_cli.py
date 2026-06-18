"""Tests for the OWASP scan CLI command and interactive menu integration."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from ghostmirror.app.cli import app

runner = CliRunner()


def test_scan_owasp_command_not_found_without_project():
    """Running `scan owasp` without project should fail gracefully."""
    result = runner.invoke(app, ["scan", "owasp"])
    assert result.exit_code != 0 or "projeto" in result.stdout.lower()


@patch("ghostmirror.app.cli.Prompt.ask")
@patch("ghostmirror.app.cli._render_projects_table")
def test_scan_owasp_no_project_interactive(
    mock_render,
    mock_prompt,
):
    """Test scan owasp command when no project is provided (interactive selection)."""
    mock_prompt.return_value = "non-existent-project"
    result = runner.invoke(app, ["scan", "owasp", "--project", "non-existent-project"])
    assert result.exit_code != 0


@patch("ghostmirror.modules.owasp.scanner.OWASPScanner.run")
@patch("ghostmirror.app.cli.bootstrap")
def test_scan_owasp_command(mock_bootstrap, mock_scanner, tmp_path):
    """Test successful owasp scan execution via CLI."""
    mock_handle = MagicMock()
    mock_handle.path = tmp_path
    mock_handle.slug = "test-owasp-project"

    mock_app_ctx = MagicMock()
    mock_app_ctx.projects.open_project.return_value = mock_handle
    mock_bootstrap.return_value = mock_app_ctx

    from ghostmirror.modules.models.finding import ScanResultModel

    scan_res = ScanResultModel(
        scanner_name="owasp",
        target="example.com",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        status="completed",
        findings=[],
        statistics={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )
    mock_scanner.return_value = scan_res

    # Create profile file
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir(parents=True, exist_ok=True)
    import json
    with open(profile_dir / "owasp_profile.json", "w") as f:
        json.dump({
            "target": "example.com",
            "categories": ["Broken Access Control Indicators"],
            "findings": [{
                "category": "Broken Access Control Indicators",
                "title": "Admin exposed",
                "description": "Test",
                "severity": "HIGH",
                "target": "example.com",
                "evidence": "",
                "recommendation": "Fix admin panel",
                "owasp_score": 15,
                "id": "test-id",
            }],
            "risk_score": 15,
            "risk_level": "LOW",
            "recommendations": ["Fix admin panel"],
            "scan_timestamp": "2024-01-01",
        }, f)

    result = runner.invoke(app, [
        "scan", "owasp",
        "--project", "test-owasp-project",
        "--target", "example.com",
    ])

    assert result.exit_code == 0
    assert "OWASP ASSESSMENT COMPLETE" in result.stdout
    assert "example.com" in result.stdout


@patch("ghostmirror.modules.owasp.scanner.OWASPScanner.run")
@patch("ghostmirror.app.cli.bootstrap")
def test_scan_owasp_without_profile(mock_bootstrap, mock_scanner, tmp_path):
    """Test OWASP scan output when profile file is missing (graceful degradation)."""
    mock_handle = MagicMock()
    mock_handle.path = tmp_path
    mock_handle.slug = "test-owasp-project"

    mock_app_ctx = MagicMock()
    mock_app_ctx.projects.open_project.return_value = mock_handle
    mock_bootstrap.return_value = mock_app_ctx

    from ghostmirror.modules.models.finding import ScanResultModel

    scan_res = ScanResultModel(
        scanner_name="owasp",
        target="example.com",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        status="completed",
        findings=[],
        statistics={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )
    mock_scanner.return_value = scan_res

    result = runner.invoke(app, [
        "scan", "owasp",
        "--project", "test-owasp-project",
        "--target", "example.com",
    ])

    assert result.exit_code == 0
