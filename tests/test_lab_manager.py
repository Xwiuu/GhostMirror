"""Tests for the lab manager and safety guard."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.core.exceptions import LabNotFoundError, LabSafetyViolation
from ghostmirror.models.scope import (
    AllowedTests,
    ScopeModel,
    ScopeProjectInfo,
    ScopeTargets,
)
from ghostmirror.modules.lab.catalog import LabCatalog
from ghostmirror.modules.lab.manager import LabManager, LabSafetyGuard


@pytest.fixture(autouse=True)
def reset_catalog() -> None:
    LabCatalog.reset()
    yield
    LabCatalog.reset()


class TestLabManager:
    def test_init(self) -> None:
        manager = LabManager()
        assert manager.catalog is LabCatalog
        assert manager.factory is not None

    def test_start_valid_lab(self) -> None:
        manager = LabManager()
        with patch("ghostmirror.modules.lab.manager.DockerRunner.up") as mock_up:
            mock_up.return_value = {"success": True, "stdout": "", "stderr": ""}
            result = manager.start("juice-shop")
            assert result["success"] is True
            mock_up.assert_called_once()

    def test_start_invalid_lab_raises(self) -> None:
        manager = LabManager()
        with pytest.raises(LabNotFoundError):
            manager.start("nonexistent")

    @patch("ghostmirror.modules.lab.manager.DockerRunner.up")
    def test_start_docker_failure(self, mock_up: MagicMock) -> None:
        mock_up.return_value = {"success": False, "stdout": "", "stderr": "error"}
        manager = LabManager()
        result = manager.start("juice-shop")
        assert result["success"] is False

    def test_stop_valid_lab(self) -> None:
        manager = LabManager()
        with patch("ghostmirror.modules.lab.manager.DockerRunner.down") as mock_down:
            mock_down.return_value = {"success": True, "stdout": "", "stderr": ""}
            result = manager.stop("juice-shop")
            assert result["success"] is True

    def test_stop_invalid_lab_raises(self) -> None:
        manager = LabManager()
        with pytest.raises(LabNotFoundError):
            manager.stop("nonexistent")

    def test_status_returns_list(self) -> None:
        manager = LabManager()
        with patch("ghostmirror.modules.lab.manager.DockerRunner.is_running") as mock_running:
            mock_running.return_value = False
            entries = manager.status()
            assert len(entries) == 4
            for entry in entries:
                assert "id" in entry
                assert "name" in entry
                assert "running" in entry
                assert entry["running"] is False

    def test_health_returns_health_checker(self) -> None:
        manager = LabManager()
        health = manager.health("juice-shop")
        assert health.lab.id == "juice-shop"

    def test_create_project(self) -> None:
        manager = LabManager()
        with patch.object(manager.factory, "create") as mock_create:
            mock_create.return_value = MagicMock(slug="lab-juice-shop")
            handle = manager.create_project("juice-shop")
            assert handle.slug == "lab-juice-shop"
            mock_create.assert_called_once()

    def test_find_project_none(self) -> None:
        manager = LabManager()
        result = manager.find_project("nonexistent")
        assert result is None

    def test_status_summary_matches_status(self) -> None:
        manager = LabManager()
        with patch.object(manager, "status") as mock_status:
            mock_status.return_value = [{"id": "juice-shop", "running": False}]
            summary = manager.status_summary()
            assert summary == mock_status.return_value


class TestLabSafetyGuard:
    def test_non_lab_scope_passes(self) -> None:
        scope = ScopeModel(
            project=ScopeProjectInfo(client="Client", name="Project", lab=False),
            targets=ScopeTargets(domains=["example.com"]),
        )
        LabSafetyGuard.validate(scope)  # should not raise

    def test_lab_scope_localhost_passes(self) -> None:
        scope = ScopeModel(
            project=ScopeProjectInfo(client="GhostMirror Lab", name="Test Lab", lab=True),
            targets=ScopeTargets(
                domains=[],
                ips=["127.0.0.1"],
                urls=["http://localhost:3000"],
            ),
        )
        LabSafetyGuard.validate(scope)  # should not raise

    def test_lab_scope_private_ip_passes(self) -> None:
        scope = ScopeModel(
            project=ScopeProjectInfo(client="GhostMirror Lab", name="Test Lab", lab=True),
            targets=ScopeTargets(domains=[], ips=["192.168.1.1"]),
        )
        LabSafetyGuard.validate(scope)  # should not raise

    def test_lab_scope_public_domain_raises(self) -> None:
        scope = ScopeModel(
            project=ScopeProjectInfo(client="GhostMirror Lab", name="Test Lab", lab=True),
            targets=ScopeTargets(domains=["example.com"]),
        )
        with pytest.raises(LabSafetyViolation, match="not allowed"):
            LabSafetyGuard.validate(scope)

    def test_lab_scope_public_ip_raises(self) -> None:
        scope = ScopeModel(
            project=ScopeProjectInfo(client="GhostMirror Lab", name="Test Lab", lab=True),
            targets=ScopeTargets(domains=[], ips=["8.8.8.8"]),
        )
        with pytest.raises(LabSafetyViolation, match="public"):
            LabSafetyGuard.validate(scope)

    def test_lab_scope_public_url_raises_at_model_level(self) -> None:
        with pytest.raises(Exception, match="not allowed in lab scope"):
            ScopeTargets(domains=[], ips=[], urls=["http://example.com:3000"])

    def test_lab_scope_host_docker_internal_passes(self) -> None:
        scope = ScopeModel(
            project=ScopeProjectInfo(client="GhostMirror Lab", name="Test Lab", lab=True),
            targets=ScopeTargets(domains=["host.docker.internal"], ips=[]),
        )
        LabSafetyGuard.validate(scope)  # should not raise

    def test_lab_scope_private_network_range_passes(self) -> None:
        scope = ScopeModel(
            project=ScopeProjectInfo(client="GhostMirror Lab", name="Test Lab", lab=True),
            targets=ScopeTargets(domains=[], ips=["10.0.0.0/8"]),
        )
        LabSafetyGuard.validate(scope)

    def test_lab_scope_public_network_range_raises(self) -> None:
        scope = ScopeModel(
            project=ScopeProjectInfo(client="GhostMirror Lab", name="Test Lab", lab=True),
            targets=ScopeTargets(domains=[], ips=["1.0.0.0/8"]),
        )
        with pytest.raises(LabSafetyViolation, match="public"):
            LabSafetyGuard.validate(scope)
