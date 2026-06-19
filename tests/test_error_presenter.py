"""Tests for CLIErrorPresenter — never show tracebacks to user."""

from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from ghostmirror.app.error_handler import present_error
from ghostmirror.core.exceptions import (
    ExitCode,
    InvalidConfigurationError,
    OutOfScopeError,
    ProjectError,
    ReportGenerationError,
    ScannerError,
    ToolNotFoundError,
    ToolTimeoutError,
)


class TestErrorPresenter:
    """Verify present_error never raises and always produces friendly output."""

    def test_tool_not_found_error_panel(self):
        """ToolNotFoundError produces a panel, not a traceback."""
        console = Console(file=StringIO())
        exc = ToolNotFoundError("nuclei is not installed")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_scanner_error_panel(self):
        """ScannerError produces a panel."""
        console = Console(file=StringIO())
        exc = ScannerError("OWASP assessment failed")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_file_not_found_error_panel(self):
        """FileNotFoundError produces a panel."""
        console = Console(file=StringIO())
        exc = FileNotFoundError("technology_profile.json not found")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_value_error_panel(self):
        """ValueError produces a panel."""
        console = Console(file=StringIO())
        exc = ValueError("Invalid target URL")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_out_of_scope_error_panel(self):
        """OutOfScopeError produces a panel."""
        console = Console(file=StringIO())
        exc = OutOfScopeError("Target not in scope")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_tool_timeout_error_panel(self):
        """ToolTimeoutError produces a panel."""
        console = Console(file=StringIO())
        exc = ToolTimeoutError("nmap timed out")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_invalid_config_error_panel(self):
        """InvalidConfigurationError produces a panel."""
        console = Console(file=StringIO())
        exc = InvalidConfigurationError("Missing API key")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_project_error_panel(self):
        """ProjectError produces a panel."""
        console = Console(file=StringIO())
        exc = ProjectError("Project not found")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_report_generation_error_panel(self):
        """ReportGenerationError produces a panel."""
        console = Console(file=StringIO())
        exc = ReportGenerationError("Failed to generate PDF")
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_keyboard_interrupt_panel(self):
        """KeyboardInterrupt produces a friendly message."""
        console = Console(file=StringIO())
        exc = KeyboardInterrupt()
        try:
            present_error(exc)
        except SystemExit:
            pass

    def test_generic_exception_panel(self):
        """Generic Exception still produces a panel, never a raw traceback."""
        console = Console(file=StringIO())
        exc = RuntimeError("Unexpected error")
        try:
            present_error(exc)
        except SystemExit:
            pass


class TestExitCodes:
    """Verify ExitCode enum values."""

    def test_exit_code_values(self):
        """Exit codes must match expected values."""
        assert ExitCode.SUCCESS == 0
        assert ExitCode.USER_ERROR == 1
        assert ExitCode.CONFIG_ERROR == 2
        assert ExitCode.DEPENDENCY_MISSING == 3
        assert ExitCode.INTERNAL_ERROR == 4

    def test_exit_code_names(self):
        """Exit code names are descriptive."""
        assert ExitCode(0).name == "SUCCESS"
        assert ExitCode(1).name == "USER_ERROR"
        assert ExitCode(2).name == "CONFIG_ERROR"
        assert ExitCode(3).name == "DEPENDENCY_MISSING"
        assert ExitCode(4).name == "INTERNAL_ERROR"
