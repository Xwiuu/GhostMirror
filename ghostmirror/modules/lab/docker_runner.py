"""Docker Runner — subprocess wrapper for docker compose lifecycle commands."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

from ghostmirror.core.exceptions import LabDockerError, ToolNotFoundError


class DockerRunner:
    """Manages docker compose lifecycle for lab environments."""

    def __init__(self, compose_file: str | Path) -> None:
        self.compose_file = Path(compose_file).resolve()

    # ------------------------------------------------------------------ #
    # Availability
    # ------------------------------------------------------------------ #
    @staticmethod
    def is_docker_available() -> bool:
        """Return True if the docker CLI is installed and reachable.

        Does NOT verify the daemon is running — use :meth:`is_daemon_running`
        for that.
        """
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def is_daemon_running() -> bool:
        """Return True if the Docker daemon is reachable."""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def is_compose_command_available() -> bool:
        """Check if 'docker compose' (v2) or 'docker-compose' (v1) is available."""
        for cmd in (["docker", "compose", "version"], ["docker-compose", "--version"]):
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return False

    @staticmethod
    def _compose_cmd() -> list[str]:
        """Return the appropriate docker compose CLI command."""
        try:
            subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return ["docker", "compose"]
        except FileNotFoundError:
            return ["docker-compose"]

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def up(self, wait: bool = True, timeout: int = 120) -> dict[str, Any]:
        """Start the lab environment.

        Returns a dict with ``success``, ``stdout``, ``stderr``.
        """
        self._assert_compose_exists()
        cmd = self._compose_cmd() + ["-f", str(self.compose_file), "up", "-d"]
        return self._run(cmd, timeout=timeout)

    def down(self, timeout: int = 60) -> dict[str, Any]:
        """Stop and remove the lab environment."""
        self._assert_compose_exists()
        cmd = self._compose_cmd() + ["-f", str(self.compose_file), "down"]
        return self._run(cmd, timeout=timeout)

    def ps(self, timeout: int = 30) -> list[dict[str, Any]]:
        """Return a list of container status dicts for this compose project.

        Each dict has keys: ``name``, ``status``, ``ports``, ``state``.
        """
        self._assert_compose_exists()
        cmd = self._compose_cmd() + [
            "-f",
            str(self.compose_file),
            "ps",
            "--format",
            "json",
        ]
        result = self._run(cmd, timeout=timeout)
        stdout = result.get("stdout")
        if not result["success"] or not stdout or not stdout.strip():
            return []

        import json as j

        containers: list[dict[str, Any]] = []
        for line in result["stdout"].strip().splitlines():
            try:
                info = j.loads(line)
                containers.append(
                    {
                        "name": info.get("Name", info.get("Service", "unknown")),
                        "status": info.get("Status", "unknown"),
                        "state": info.get("State", "unknown"),
                        "ports": info.get("Ports", ""),
                    }
                )
            except (j.JSONDecodeError, KeyError):
                continue
        return containers

    def is_running(self, timeout: int = 15) -> bool:
        """Return True if all services in the compose file are running."""
        containers = self.ps(timeout=timeout)
        if not containers:
            return False
        return all(
            c.get("state", "").lower() == "running" for c in containers
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _assert_compose_exists(self) -> None:
        if not self.compose_file.exists():
            raise LabDockerError(
                f"Compose file not found: {self.compose_file}"
            )

    @staticmethod
    def _run(cmd: list[str], timeout: int) -> dict[str, Any]:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return {
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except FileNotFoundError:
            raise ToolNotFoundError(
                "Docker CLI not found. Install Docker (https://docs.docker.com/get-docker/)"
            ) from None
        except subprocess.TimeoutExpired:
            raise LabDockerError(
                f"Docker command timed out after {timeout}s: {' '.join(cmd)}"
            ) from None
