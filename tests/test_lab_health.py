"""Tests for the lab health module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ghostmirror.core.exceptions import LabNotFoundError
from ghostmirror.modules.lab.catalog import LabCatalog
from ghostmirror.modules.lab.health import LabHealth


@pytest.fixture(autouse=True)
def reset_catalog() -> None:
    LabCatalog.reset()
    yield
    LabCatalog.reset()


class TestLabHealth:
    def test_init_valid_lab(self) -> None:
        health = LabHealth("juice-shop")
        assert health.lab.id == "juice-shop"
        assert health.docker is not None

    def test_init_invalid_lab_raises(self) -> None:
        with pytest.raises(LabNotFoundError):
            LabHealth("nonexistent")

    def _patch_all_checks(self, health: LabHealth, **kwargs: bool) -> None:
        """Patch all 5 health checks with optional overrides."""
        defaults = dict.fromkeys(LabHealth.CHECK_NAMES, True)
        defaults.update(kwargs)
        for name, value in defaults.items():
            attr = {
                "Docker available": "_check_docker",
                "Compose file exists": "_check_compose_file",
                "Container running": "_check_container_running",
                "Port open": "_check_port",
                "URL responding": "_check_url",
            }[name]
            patcher = patch.object(LabHealth, attr, return_value=value)
            patcher.start()

    def test_check_all_passes(self) -> None:
        health = LabHealth("juice-shop")
        with patch.object(LabHealth, "_check_docker", return_value=True):
            with patch.object(LabHealth, "_check_compose_file", return_value=True):
                with patch.object(LabHealth, "_check_container_running", return_value=True):
                    with patch.object(LabHealth, "_check_port", return_value=True):
                        with patch.object(LabHealth, "_check_url", return_value=True):
                            results = health.check_all()
                            assert health.is_healthy() is True
        for name in LabHealth.CHECK_NAMES:
            assert results[name] is True, f"{name} should be True"

    def test_summary_returns_list(self) -> None:
        health = LabHealth("juice-shop")
        with patch.object(LabHealth, "_check_docker", return_value=True):
            with patch.object(LabHealth, "_check_compose_file", return_value=True):
                with patch.object(LabHealth, "_check_container_running", return_value=True):
                    with patch.object(LabHealth, "_check_port", return_value=True):
                        with patch.object(LabHealth, "_check_url", return_value=True):
                            summary = health.summary()
        assert len(summary) == 5
        for entry in summary:
            assert "check" in entry
            assert "passed" in entry

    def test_check_docker_fails_independently(self) -> None:
        health = LabHealth("juice-shop")
        with patch.object(LabHealth, "_check_docker", return_value=False):
            with patch.object(LabHealth, "_check_compose_file", return_value=True):
                with patch.object(LabHealth, "_check_container_running", return_value=True):
                    with patch.object(LabHealth, "_check_port", return_value=True):
                        with patch.object(LabHealth, "_check_url", return_value=True):
                            results = health.check_all()
                            assert results["Docker available"] is False
                            assert health.is_healthy() is False

    def test_compose_file_fails_independently(self) -> None:
        health = LabHealth("juice-shop")
        with patch.object(LabHealth, "_check_compose_file", return_value=False):
            with patch.object(LabHealth, "_check_docker", return_value=True):
                with patch.object(LabHealth, "_check_container_running", return_value=True):
                    with patch.object(LabHealth, "_check_port", return_value=True):
                        with patch.object(LabHealth, "_check_url", return_value=True):
                            results = health.check_all()
                            assert results["Compose file exists"] is False

    def test_check_docker_real(self) -> None:
        health = LabHealth("juice-shop")
        with patch("ghostmirror.modules.lab.health.DockerRunner.is_docker_available", return_value=True):
            with patch("ghostmirror.modules.lab.health.DockerRunner.is_daemon_running", return_value=False):
                assert health._check_docker() is False

    def test_check_compose_file_real(self) -> None:
        health = LabHealth("juice-shop")
        with patch("ghostmirror.modules.lab.health.Path.exists", return_value=True):
            assert health._check_compose_file() is True
        with patch("ghostmirror.modules.lab.health.Path.exists", return_value=False):
            assert health._check_compose_file() is False
