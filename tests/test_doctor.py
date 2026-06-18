from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.modules.platform.doctor import DoctorEngine


@pytest.fixture()
def doctor_engine(home_dir: Path) -> DoctorEngine:
    config = ConfigManager(base_dir=home_dir)
    config.load()
    return DoctorEngine(config)


class TestDoctorEngine:
    def test_init(self, doctor_engine: DoctorEngine):
        assert doctor_engine.diagnostics is not None

    def test_run_doctor_all_ok(self, doctor_engine: DoctorEngine):
        with patch.object(
            doctor_engine.diagnostics, "run_diagnostics",
            return_value={
                "environment": {"python_version": "3.12.0", "in_virtual_env": True},
                "filesystem": {"projects": True, "logs": True, "reports": True},
                "binaries": {"nmap": True, "whatweb": True, "nuclei": True, "weasyprint": True, "docker": True},
                "docker_daemon_running": True,
                "libraries": {"pydantic": True, "loguru": True, "yaml": True, "weasyprint": True},
            },
        ):
            result = doctor_engine.run_doctor()
            assert result is True

    def test_run_doctor_with_failures(self, doctor_engine: DoctorEngine):
        with patch.object(
            doctor_engine.diagnostics, "run_diagnostics",
            return_value={
                "environment": {"python_version": "3.12.0", "in_virtual_env": False},
                "filesystem": {"projects": False, "logs": True, "reports": True},
                "binaries": {"nmap": False, "whatweb": False, "nuclei": False, "weasyprint": False, "docker": False},
                "docker_daemon_running": False,
                "libraries": {"pydantic": False, "loguru": False, "yaml": False, "weasyprint": False},
            },
        ):
            result = doctor_engine.run_doctor()
            assert result is False
