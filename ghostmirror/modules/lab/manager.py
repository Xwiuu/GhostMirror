"""Lab Manager — orchestrates the lifecycle of lab environments."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.exceptions import LabSafetyViolation, ScopeViolationError
from ghostmirror.core.logger import get_logger
from ghostmirror.core.project_manager import ProjectManager, ProjectHandle
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.models.scope import ScopeModel
from ghostmirror.modules.lab.catalog import LabCatalog
from ghostmirror.modules.lab.docker_runner import DockerRunner
from ghostmirror.modules.lab.health import LabHealth
from ghostmirror.modules.lab.project_factory import LabProjectFactory

logger = get_logger()


# --------------------------------------------------------------------------- #
# Safety Guard
# --------------------------------------------------------------------------- #
class LabSafetyGuard:
    """Validates that lab-scoped projects only target allowed local/private hosts.

    Invoked before any scan operation against a lab project.
    """

    ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]

    @classmethod
    def validate(cls, scope: ScopeModel) -> None:
        """Raise :class:`LabSafetyViolation` if the scope targets a non-local host.

        Only applies when ``scope.project.lab == True``.
        """
        if not scope.project.lab:
            return

        for domain in scope.targets.domains:
            if domain not in cls.ALLOWED_HOSTS:
                raise LabSafetyViolation(
                    f"Lab target domain {domain!r} is not allowed. "
                    "Lab projects can only target localhost or private IPs."
                )

        for ip_str in scope.targets.ips:
            try:
                net = ipaddress.ip_network(ip_str, strict=False)
            except ValueError:
                raise LabSafetyViolation(
                    f"Invalid IP/CIDR in lab scope: {ip_str!r}"
                ) from None

            is_private = any(net.overlaps(r) for r in cls.PRIVATE_RANGES)
            if not is_private and str(net.network_address) not in cls.ALLOWED_HOSTS:
                raise LabSafetyViolation(
                    f"Lab target IP/network {ip_str!r} is public. "
                    "Only localhost and private IPs are allowed."
                )

        for url_str in scope.targets.urls:
            from urllib.parse import urlparse

            host = urlparse(url_str).hostname or ""
            if host in cls.ALLOWED_HOSTS:
                continue
            try:
                addr = ipaddress.ip_address(host)
                if not any(addr in net for net in cls.PRIVATE_RANGES):
                    raise LabSafetyViolation(
                        f"Lab URL {url_str!r} points to a public host {host!r}."
                    )
            except ValueError:
                raise LabSafetyViolation(
                    f"Lab URL {url_str!r} contains an invalid host {host!r}."
                ) from None

        logger.info("LAB_SAFETY_GUARD_PASSED")


# --------------------------------------------------------------------------- #
# Manager
# --------------------------------------------------------------------------- #
class LabManager:
    """High-level orchestrator for lab environment lifecycle."""

    def __init__(
        self,
        config: ConfigManager | None = None,
    ) -> None:
        self.config = config or ConfigManager()
        self.config.load()
        self.catalog = LabCatalog
        self.factory = LabProjectFactory(config=self.config)
        self.project_manager = ProjectManager(
            config=self.config, scope_manager=ScopeManager()
        )

    # ------------------------------------------------------------------ #
    # Start
    # ------------------------------------------------------------------ #
    def start(self, lab_id: str) -> dict[str, Any]:
        """Start a lab environment.

        Returns the result of ``docker compose up -d``.
        Raises ``LabNotFoundError`` if the lab does not exist.
        """
        lab = self.catalog.get(lab_id)
        runner = DockerRunner(lab.docker_compose_file)

        logger.info("LAB_START id={} compose={}", lab_id, lab.docker_compose_file)
        result = runner.up()
        if result["success"]:
            logger.info("LAB_STARTED id={}", lab_id)
        else:
            logger.error("LAB_START_FAILED id={} stderr={}", lab_id, result["stderr"])

        return result

    # ------------------------------------------------------------------ #
    # Stop
    # ------------------------------------------------------------------ #
    def stop(self, lab_id: str) -> dict[str, Any]:
        """Stop and remove a lab environment.

        Returns the result of ``docker compose down``.
        """
        lab = self.catalog.get(lab_id)
        runner = DockerRunner(lab.docker_compose_file)

        logger.info("LAB_STOP id={} compose={}", lab_id, lab.docker_compose_file)
        result = runner.down()
        if result["success"]:
            logger.info("LAB_STOPPED id={}", lab_id)
        else:
            logger.error("LAB_STOP_FAILED id={} stderr={}", lab_id, result["stderr"])

        return result

    # ------------------------------------------------------------------ #
    # Status
    # ------------------------------------------------------------------ #
    def status(self) -> list[dict[str, Any]]:
        """Return status of all registered lab environments."""
        entries: list[dict[str, Any]] = []
        for lab in self.catalog.get_all():
            runner = DockerRunner(lab.docker_compose_file)
            running = runner.is_running()
            entries.append(
                {
                    "id": lab.id,
                    "name": lab.name,
                    "running": running,
                    "port": lab.default_port,
                    "url": lab.default_url,
                }
            )
        return entries

    # ------------------------------------------------------------------ #
    # Health
    # ------------------------------------------------------------------ #
    def health(self, lab_id: str) -> LabHealth:
        """Return a :class:`LabHealth` instance for the given lab."""
        return LabHealth(lab_id)

    # ------------------------------------------------------------------ #
    # Create project
    # ------------------------------------------------------------------ #
    def create_project(self, lab_id: str) -> ProjectHandle:
        """Create a GhostMirror project for the given lab."""
        lab = self.catalog.get(lab_id)
        logger.info("LAB_CREATE_PROJECT id={}", lab_id)
        return self.factory.create(lab)

    # ------------------------------------------------------------------ #
    # Find project
    # ------------------------------------------------------------------ #
    def find_project(self, lab_id: str) -> Path | None:
        """Return the project path for a lab, or None."""
        return LabProjectFactory.find_lab_project(
            self.config.projects_dir, lab_id
        )

    # ------------------------------------------------------------------ #
    # Safety guard helper
    # ------------------------------------------------------------------ #
    @staticmethod
    def check_safety(scope: ScopeModel) -> None:
        """Validate lab project scope. Raises if unsafe."""
        LabSafetyGuard.validate(scope)

    # ------------------------------------------------------------------ #
    # Status summary (for CLI table)
    # ------------------------------------------------------------------ #
    def status_summary(self) -> list[dict[str, Any]]:
        """Return a flat list of dicts for CLI rendering."""
        return self.status()
