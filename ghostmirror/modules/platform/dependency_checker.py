"""Generic dependency validation interface for system binaries and libraries."""

from __future__ import annotations

import importlib
import importlib.util
import shutil
import subprocess

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.core.logger import get_logger

logger = get_logger()


class DependencyChecker:
    """Validates the availability of system commands and importable python modules."""

    BINARY_HELP_URLS: dict[str, str] = {
        "nmap": "https://nmap.org/download.html",
        "whatweb": "https://github.com/urbanadventurer/WhatWeb",
        "nuclei": "https://github.com/projectdiscovery/nuclei",
        "weasyprint": "https://weasyprint.org/",
        "docker": "https://www.docker.com/get-started",
    }

    @classmethod
    def check_binary(cls, binary_name: str, raise_error: bool = False) -> bool:
        """Validate if the binary exists in system PATH.

        Parameters
        ----------
        binary_name : str
            The executable name (e.g. 'nmap').
        raise_error : bool
            If True, raises ToolNotFoundError on failure.
        """
        # shutil.which works on Windows too for .exe files
        available = shutil.which(binary_name) is not None
        
        # fallback for weasyprint checking
        if not available and binary_name == "weasyprint":
            available = cls.check_python_library("weasyprint")

        if not available and raise_error:
            url = cls.BINARY_HELP_URLS.get(binary_name, "https://github.com/google/ghostmirror")
            logger.error("DEPENDENCY_MISSING binary={} install_url={}", binary_name, url)
            raise ToolNotFoundError(
                f"Ferramenta '{binary_name}' não encontrada.\nInstale:\n{url}"
            )
        return available

    @staticmethod
    def check_python_library(library_name: str) -> bool:
        """Check if a Python library is importable in the current context.
        Uses find_spec to avoid executing module-level code (side effects).
        """
        try:
            spec = importlib.util.find_spec(library_name)
            if spec is None:
                return False
            return True
        except Exception:
            return False

    @staticmethod
    def check_docker_daemon() -> bool:
        """Verify if Docker is running and communicating with the client."""
        if not shutil.which("docker"):
            return False
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception:
            return False
