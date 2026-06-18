"""Environment information collector for runtime analysis."""

from __future__ import annotations

import os
import platform
import sys
from typing import Any


class EnvironmentCollector:
    """Retrieves OS and Python runtime specifications."""

    @staticmethod
    def get_runtime_info() -> dict[str, Any]:
        """Gathers system, platform, python and environment information."""
        # Detect virtual environment
        in_virtual_env = (
            sys.prefix != sys.base_prefix
            or "VIRTUAL_ENV" in os.environ
            or hasattr(sys, "real_prefix")
        )

        venv_path = os.environ.get("VIRTUAL_ENV") or sys.prefix

        # Detect docker
        in_docker = os.path.exists("/.dockerenv")

        return {
            "python_version": sys.version.split()[0],
            "python_executable": sys.executable,
            "os_system": platform.system(),
            "os_release": platform.release(),
            "os_architecture": platform.machine(),
            "in_virtual_env": in_virtual_env,
            "virtual_env_path": venv_path if in_virtual_env else None,
            "in_docker": in_docker,
            "ghostmirror_home": os.environ.get("GHOSTMIRROR_HOME"),
        }
