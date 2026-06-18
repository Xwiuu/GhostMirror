"""Tests for Doctor Fix mode."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.platform.doctor_fix import INSTALL_COMMANDS


class TestDoctorFix:
    def test_install_commands_defined(self):
        """All expected tools should have install commands."""
        expected = ["nmap", "whatweb", "nuclei", "weasyprint", "docker"]
        for tool in expected:
            assert tool in INSTALL_COMMANDS, f"{tool} missing from INSTALL_COMMANDS"
            assert INSTALL_COMMANDS[tool], f"{tool} has empty install command"

    def test_run_doctor_fix_no_issues(self):
        """When no issues found, returns True."""
        from ghostmirror.core.config_manager import ConfigManager
        from ghostmirror.modules.platform.doctor_fix import run_doctor_fix

        config = MagicMock(spec=ConfigManager)
        with patch("ghostmirror.modules.platform.diagnostics.PlatformDiagnostics.run_diagnostics") as mock_diag:
            mock_diag.return_value = {
                "environment": {"python_version": "3.12", "in_virtual_env": True},
                "filesystem": {"projects": True, "logs": True, "reports": True},
                "binaries": {"nmap": True, "whatweb": True, "nuclei": True, "weasyprint": True, "docker": True},
                "docker_daemon_running": True,
                "libraries": {"pydantic": True, "loguru": True, "yaml": True, "weasyprint": True},
                "lab": {"catalog_valid": True, "compose_files_present": True},
            }
            result = run_doctor_fix(config)
            assert result is True
