from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.modules.platform.health_check import HealthCheckEngine


@pytest.fixture()
def health_engine(home_dir: Path) -> HealthCheckEngine:
    config = ConfigManager(base_dir=home_dir)
    config.load()
    return HealthCheckEngine(config)


class TestHealthCheckEngine:
    def test_init(self, health_engine: HealthCheckEngine):
        assert health_engine.diagnostics is not None

    def test_run_health_check_healthy(self, health_engine: HealthCheckEngine, tmp_path: Path):
        fake_templates = tmp_path / "knowledge" / "cves" / "nuclei_template_map.json"
        fake_templates.parent.mkdir(parents=True, exist_ok=True)
        fake_templates.write_text("{}", encoding="utf-8")

        with patch.object(
            health_engine.diagnostics, "run_diagnostics",
            return_value={
                "environment": {"python_version": "3.12.0", "in_virtual_env": True},
                "filesystem": {"projects": True, "logs": True, "reports": True},
                "binaries": {"nmap": True, "whatweb": True, "nuclei": True, "weasyprint": True, "docker": True},
                "docker_daemon_running": True,
                "libraries": {"pydantic": True, "loguru": True, "yaml": True, "weasyprint": True},
            },
        ):
            result = health_engine.run_health_check()
            assert result is True

    def test_run_health_check_unhealthy(self, health_engine: HealthCheckEngine, tmp_path: Path):
        fake_templates = tmp_path / "knowledge" / "cves"
        fake_templates.mkdir(parents=True, exist_ok=True)

        with patch.object(
            health_engine.diagnostics, "run_diagnostics",
            return_value={
                "environment": {"python_version": "3.12.0", "in_virtual_env": True},
                "filesystem": {"projects": False, "logs": True, "reports": True},
                "binaries": {"nmap": False, "whatweb": True, "nuclei": True, "weasyprint": True, "docker": False},
                "docker_daemon_running": False,
                "libraries": {"pydantic": True, "loguru": True, "yaml": True, "weasyprint": True},
            },
        ):
            with patch(
                "ghostmirror.modules.platform.health_check.Path",
                return_value=fake_templates / "nuclei_template_map.json",
            ):
                pass
            result = health_engine.run_health_check()
            assert result is False

    def test_template_check_missing(self, health_engine: HealthCheckEngine, tmp_path: Path):
        with patch.object(
            health_engine.diagnostics, "run_diagnostics",
            return_value={
                "environment": {"python_version": "3.12.0", "in_virtual_env": True},
                "filesystem": {"projects": True, "logs": True, "reports": True},
                "binaries": {"nmap": True, "whatweb": True, "nuclei": True, "weasyprint": True, "docker": True},
                "docker_daemon_running": True,
                "libraries": {"pydantic": True, "loguru": True, "yaml": True, "weasyprint": True},
            },
        ):
            with patch("pathlib.Path.exists", return_value=False):
                result = health_engine.run_health_check()
                assert result is False
