"""Unit tests for the CLI commands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import httpx
from typer.testing import CliRunner

from ghostmirror.app.cli import app


def test_cli_version() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "GhostMirror" in result.stdout
    assert "v1.0-alpha" in result.stdout
    assert "Build:" in result.stdout


def test_cli_config(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    assert "app.name" in result.stdout
    assert "paths.projects" in result.stdout


def test_cli_create_list_open(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()

    # 1. Create a project
    create_result = runner.invoke(
        app,
        ["create", "-c", "Acme Corp", "-n", "External Audit", "-d", "acme.org", "--notes", "Test notes"],
    )
    assert create_result.exit_code == 0
    assert "Projeto criado" in create_result.stdout

    # 2. List projects
    list_result = runner.invoke(app, ["list"])
    assert list_result.exit_code == 0
    assert "acme-corp" in list_result.stdout


    # 3. Open project
    open_result = runner.invoke(app, ["open", "acme-corp-external-audit"])
    assert open_result.exit_code == 0
    assert "acme-corp-external-audit" in open_result.stdout
    assert "acme.org" in open_result.stdout


def test_cli_open_not_found(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["open", "non-existent-project"])
    assert result.exit_code == 1
    assert "Erro" in result.stdout


@patch("httpx.Client")
def test_cli_scan_headers_flow(mock_client_class, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()

    # 1. Create project
    runner.invoke(app, ["create", "-c", "Acme Corp", "-n", "External Audit", "-d", "acme.org"])

    # 2. Run scan headers against out-of-scope target
    blocked_result = runner.invoke(
        app,
        ["scan", "headers", "-p", "acme-corp-external-audit", "-t", "evil.com"],
    )
    assert blocked_result.exit_code == 1
    assert "Execução Bloqueada" in blocked_result.stdout

    # 3. Run scan headers against in-scope target
    mock_headers = httpx.Headers({
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
    })
    
    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.reason_phrase = "OK"
    mock_response.headers = mock_headers
    mock_response.url = httpx.URL("https://acme.org")

    mock_client = MagicMock()
    mock_client.get.return_value = mock_response
    mock_client_class.return_value.__enter__.return_value = mock_client

    success_result = runner.invoke(
        app,
        ["scan", "headers", "-p", "acme-corp-external-audit", "-t", "acme.org"],
    )
    assert success_result.exit_code == 0
    assert "## HEADERS SCAN COMPLETE" in success_result.stdout
    assert "Target:\nhttps://acme.org" in success_result.stdout
    assert "Findings:\n0" in success_result.stdout


def test_cli_interactive_exit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(app, ["interactive"], input="0\n")
    assert result.exit_code == 0
    assert "Encerrando GhostMirror" in result.stdout


def test_cli_interactive_doctor_and_exit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    with patch("ghostmirror.modules.platform.diagnostics.DependencyChecker.check_python_library", return_value=True):
        with patch("pathlib.Path.is_dir", return_value=True):
            # Choice 7 runs Doctor, then next prompt gets choice 0 to exit
            result = runner.invoke(app, ["interactive"], input="7\n0\n")
            assert result.exit_code == 0
            assert "Encerrando GhostMirror" in result.stdout


def test_cli_interactive_list_and_exit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    # Choice 1 (Projects), Choice 2 (list projects), then choice 0 to go back, choice 0 to exit
    result = runner.invoke(app, ["interactive"], input="1\n2\n\n0\n0\n")
    assert result.exit_code == 0
    assert "Nenhum projeto encontrado" in result.stdout
    assert "Encerrando GhostMirror" in result.stdout


def test_cli_interactive_create_and_exit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    # Choice 1 (Projects), Choice 1 (create project), then prompts for details, then choice 0 to go back, choice 0 to exit
    input_sequence = "1\n1\nAcme Corp\nMy Audit\nacme.org\nSome notes\n\n0\n0\n"
    result = runner.invoke(app, ["interactive"], input=input_sequence)
    assert result.exit_code == 0
    assert "Projeto criado e selecionado como ativo: acme-corp-my-audit" in result.stdout
    assert "Encerrando GhostMirror" in result.stdout


def test_cli_interactive_open_and_exit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    # 1. Create project
    runner.invoke(app, ["create", "-c", "Acme Corp", "-n", "My Audit"])
    
    # Choice 1 (Projects), Choice 3 (open project), slug, then choice 0 to go back, choice 0 to exit
    input_sequence = "1\n3\nacme-corp-my-audit\n\n0\n0\n"
    result = runner.invoke(app, ["interactive"], input=input_sequence)
    assert result.exit_code == 0
    assert "Projeto • acme-corp-my-audit" in result.stdout
    assert "Encerrando GhostMirror" in result.stdout


def test_cli_scan_headers_interactive_flow(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()
    # Run scan headers without --project or --target. It should prompt to select project and then select target.
    # 1. Create project
    runner.invoke(app, ["create", "-c", "Acme Corp", "-n", "My Audit", "-d", "example.com"])
    
    # 2. Run scan headers. Prompts: project slug, then target
    # We will input: acme-corp-my-audit, then example.com
    input_sequence = "acme-corp-my-audit\nexample.com\n"
    
    with patch("httpx.Client") as mock_client_class:
        mock_headers = httpx.Headers({"Content-Security-Policy": "default-src 'self'"})
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.reason_phrase = "OK"
        mock_response.headers = mock_headers
        mock_response.url = httpx.URL("https://example.com")
        
        mock_client = MagicMock()
        mock_client.get.return_value = mock_response
        mock_client_class.return_value.__enter__.return_value = mock_client

        result = runner.invoke(app, ["scan", "headers"], input=input_sequence)
        
    assert result.exit_code == 0
    assert "## HEADERS SCAN COMPLETE" in result.stdout
    assert "example.com" in result.stdout

