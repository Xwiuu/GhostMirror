"""Tests for user-friendly error handling."""

from __future__ import annotations

from io import StringIO

from ghostmirror.app.error_handler import handle_error, INSTALL_SUGGESTIONS
from ghostmirror.core.exceptions import (
    OutOfScopeError,
    ProjectAlreadyExistsError,
    ProjectNotFoundError,
    ReportGenerationError,
    ToolNotFoundError,
    ToolTimeoutError,
)


class TestErrorHandler:
    def test_tool_not_found_shows_install_suggestion(self, capsys):
        """ToolNotFoundError should show install suggestion."""
        exc = ToolNotFoundError("whatweb not found in PATH")
        handle_error(exc)
        captured = capsys.readouterr()
        assert "❌" in captured.out or "não encontrado" in captured.out

    def test_out_of_scope_error(self, capsys):
        """OutOfScopeError should show clear message."""
        exc = OutOfScopeError("Target evil.com is out of scope")
        handle_error(exc)
        captured = capsys.readouterr()
        assert "fora do escopo" in captured.out.lower() or "❌" in captured.out

    def test_tool_timeout_error(self, capsys):
        """ToolTimeoutError should show timeout message."""
        exc = ToolTimeoutError("nmap timed out")
        handle_error(exc)
        captured = capsys.readouterr()
        assert "tempo limite" in captured.out.lower() or "❌" in captured.out

    def test_project_already_exists(self, capsys):
        """ProjectError should show project error message."""
        exc = ProjectAlreadyExistsError("Project already exists")
        handle_error(exc)
        captured = capsys.readouterr()
        assert "❌" in captured.out

    def test_project_not_found(self, capsys):
        """ProjectNotFoundError should show project error."""
        exc = ProjectNotFoundError("Project not found")
        handle_error(exc)
        captured = capsys.readouterr()
        assert "❌" in captured.out

    def test_report_generation_error(self, capsys):
        """ReportGenerationError should show report error message."""
        exc = ReportGenerationError("Failed to generate PDF")
        handle_error(exc)
        captured = capsys.readouterr()
        assert "relatório" in captured.out.lower() or "❌" in captured.out

    def test_keyboard_interrupt(self, capsys):
        """KeyboardInterrupt should show cancellation message."""
        handle_error(KeyboardInterrupt())
        captured = capsys.readouterr()
        assert "cancelada" in captured.out.lower()

    def test_file_not_found(self, capsys):
        """FileNotFoundError should show file error."""
        exc = FileNotFoundError("File not found")
        handle_error(exc)
        captured = capsys.readouterr()
        assert "arquivo não encontrado" in captured.out.lower() or "❌" in captured.out

    def test_generic_exception(self, capsys):
        """Generic exception should show unexpected error."""
        exc = RuntimeError("Something broke")
        handle_error(exc)
        captured = capsys.readouterr()
        assert "inesperado" in captured.out.lower() or "❌" in captured.out

    def test_install_suggestions_contains_tools(self):
        """Install suggestions dict should have common tools."""
        assert "whatweb" in INSTALL_SUGGESTIONS
        assert "nuclei" in INSTALL_SUGGESTIONS
        assert "nmap" in INSTALL_SUGGESTIONS
        assert "docker" in INSTALL_SUGGESTIONS
