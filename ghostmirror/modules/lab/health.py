"""Lab Health — validates that a lab environment is fully operational."""

from __future__ import annotations

import socket
from pathlib import Path

import httpx

from ghostmirror.modules.lab.catalog import LabCatalog
from ghostmirror.modules.lab.docker_runner import DockerRunner


class LabHealth:
    """Performs a 5-point health check for a lab environment."""

    #: Names for each check dimension
    CHECK_NAMES = [
        "Docker available",
        "Compose file exists",
        "Container running",
        "Port open",
        "URL responding",
    ]

    def __init__(self, lab_id: str) -> None:
        self.lab = LabCatalog.get(lab_id)
        self.docker = DockerRunner(self.lab.docker_compose_file)

    def check_all(self) -> dict[str, bool]:
        """Run all 5 checks and return a dict of check_name -> passed."""
        return {
            "Docker available": self._check_docker(),
            "Compose file exists": self._check_compose_file(),
            "Container running": self._check_container_running(),
            "Port open": self._check_port(),
            "URL responding": self._check_url(),
        }

    def is_healthy(self) -> bool:
        """Return True if all 5 checks pass."""
        return all(self.check_all().values())

    def summary(self) -> list[dict[str, str | bool]]:
        """Return a list of dicts suitable for rendering in a table."""
        results = self.check_all()
        return [
            {"check": name, "passed": passed}
            for name, passed in zip(self.CHECK_NAMES, [results[k] for k in self.CHECK_NAMES])
        ]

    # ------------------------------------------------------------------ #
    # Individual checks
    # ------------------------------------------------------------------ #
    def _check_docker(self) -> bool:
        return DockerRunner.is_docker_available() and DockerRunner.is_daemon_running()

    def _check_compose_file(self) -> bool:
        return Path(self.lab.docker_compose_file).exists()

    def _check_container_running(self) -> bool:
        try:
            return self.docker.is_running()
        except Exception:
            return False

    def _check_port(self) -> bool:
        host = "127.0.0.1"
        port = self.lab.default_port
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except (OSError, socket.timeout):
            return False

    def _check_url(self) -> bool:
        url = self.lab.default_url
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(url)
                return resp.status_code < 500
        except (httpx.RequestError, httpx.TimeoutException):
            return False
