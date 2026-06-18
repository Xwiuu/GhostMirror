from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.modules.platform.dependency_checker import DependencyChecker


class TestDependencyChecker:
    def test_check_binary_found(self):
        assert DependencyChecker.check_binary("python") is True

    def test_check_binary_not_found(self):
        assert DependencyChecker.check_binary("nonexistent_tool_xyz") is False

    def test_check_binary_raises_error(self):
        with pytest.raises(ToolNotFoundError):
            DependencyChecker.check_binary("nonexistent_tool_xyz", raise_error=True)

    def test_check_binary_weasyprint_fallback(self):
        with patch("shutil.which", return_value=None):
            with patch.object(DependencyChecker, "check_python_library", return_value=False):
                result = DependencyChecker.check_binary("weasyprint")
                assert result is False

        with patch("shutil.which", return_value=None):
            with patch.object(DependencyChecker, "check_python_library", return_value=True):
                result = DependencyChecker.check_binary("weasyprint")
                assert result is True

    def test_check_python_library_found(self):
        assert DependencyChecker.check_python_library("sys") is True

    def test_check_python_library_not_found(self):
        assert DependencyChecker.check_python_library("nonexistent_lib_xyz") is False

    def test_check_docker_daemon_no_binary(self):
        with patch("shutil.which", return_value=None):
            assert DependencyChecker.check_docker_daemon() is False

    def test_check_docker_daemon_fails(self):
        with patch("shutil.which", return_value="/usr/bin/docker"):
            with patch("subprocess.run", side_effect=Exception):
                assert DependencyChecker.check_docker_daemon() is False

    def test_help_urls_present(self):
        for tool in ("nmap", "whatweb", "nuclei", "weasyprint", "docker"):
            assert tool in DependencyChecker.BINARY_HELP_URLS
            assert DependencyChecker.BINARY_HELP_URLS[tool].startswith("http")
