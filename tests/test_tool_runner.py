"""Unit tests for the ToolRunner external tool execution framework."""

from unittest.mock import MagicMock, patch
import pytest
import subprocess

from ghostmirror.integrations.base.tool_runner import (
    ToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolRunner,
    ToolTimeoutError,
)


def test_tool_runner_binary_not_found() -> None:
    runner = ToolRunner()
    with patch("shutil.which", return_value=None):
        with pytest.raises(ToolNotFoundError) as exc_info:
            runner.run("nonexistent-tool", ["--help"])
        assert "not installed or not available" in str(exc_info.value)


def test_tool_runner_success() -> None:
    runner = ToolRunner()
    
    mock_subprocess_result = MagicMock()
    mock_subprocess_result.returncode = 0
    mock_subprocess_result.stdout = "Nmap version 7.92\n"
    mock_subprocess_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run", return_value=mock_subprocess_result) as mock_run:
            result = runner.run("nmap", ["-V"])
            
            mock_run.assert_called_once_with(
                ["nmap", "-V"],
                capture_output=True,
                text=True,
                timeout=None,
                check=False,
            )
            assert result.tool_name == "nmap"
            assert result.command == "nmap -V"
            assert result.exit_code == 0
            assert result.stdout == "Nmap version 7.92\n"
            assert result.stderr == ""
            assert result.success is True
            assert result.duration >= 0.0


def test_tool_runner_exit_code_failure() -> None:
    runner = ToolRunner()
    
    mock_subprocess_result = MagicMock()
    mock_subprocess_result.returncode = 1
    mock_subprocess_result.stdout = ""
    mock_subprocess_result.stderr = "Error: Invalid target"

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run", return_value=mock_subprocess_result):
            # Without check_exit_code, should return result normally
            result = runner.run("nmap", ["invalid-target"])
            assert result.exit_code == 1
            assert result.success is False
            
            # With check_exit_code, should raise ToolExecutionError
            with pytest.raises(ToolExecutionError) as exc_info:
                runner.run("nmap", ["invalid-target"], check_exit_code=True)
            assert "failed with non-zero exit code 1" in str(exc_info.value)


def test_tool_runner_timeout() -> None:
    runner = ToolRunner()

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["nmap"], timeout=5.0, output=b"partial stdout", stderr=b"partial stderr")):
            with pytest.raises(ToolTimeoutError) as exc_info:
                runner.run("nmap", ["--slow-scan"], timeout=5.0)
            assert "execution timed out after 5.0 seconds" in str(exc_info.value)


def test_tool_runner_permission_denied() -> None:
    runner = ToolRunner()

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run", side_effect=PermissionError("Permission denied")):
            with pytest.raises(ToolError) as exc_info:
                runner.run("nmap", ["-sS"])
            assert "Permission denied" in str(exc_info.value)


def test_tool_runner_unexpected_exception() -> None:
    runner = ToolRunner()

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run", side_effect=OSError("Disk full")):
            with pytest.raises(ToolError) as exc_info:
                runner.run("nmap", ["-sS"])
            assert "Disk full" in str(exc_info.value)
