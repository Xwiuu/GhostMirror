from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.exceptions import ProjectNotFoundError
from ghostmirror.core.project_manager import ProjectManager
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.platform.status import StatusEngine


@pytest.fixture()
def status_engine(home_dir: Path) -> tuple[StatusEngine, ConfigManager, ProjectManager]:
    config = ConfigManager(base_dir=home_dir)
    config.load()
    scopes = ScopeManager()
    projects = ProjectManager(config=config, scope_manager=scopes)
    engine = StatusEngine(config=config, project_manager=projects)
    return engine, config, projects


def _create_project_with_findings(
    projects: ProjectManager,
    slug: str,
    client: str = "TestCorp",
    name: str = "Test Project",
) -> Path:
    handle = projects.create_project(client=client, name=name, domain="example.com")
    findings_dir = handle.path / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    findings_file = findings_dir / "headers.json"
    findings_file.write_text(
        json.dumps(
            {
                "scanner": "headers",
                "target": "example.com",
                "statistics": {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5},
                "findings": [],
            }
        ),
        encoding="utf-8",
    )

    execution_dir = handle.path / "execution"
    execution_dir.mkdir(parents=True, exist_ok=True)
    timeline = {
        "project": slug,
        "target": "example.com",
        "profile": "standard",
        "started_at": "2026-06-18T10:00:00",
        "finished_at": "2026-06-18T12:00:00",
        "steps": [
            {
                "name": "headers",
                "status": "completed",
                "findings_count": 15,
                "duration": 5.0,
            }
        ],
    }
    (execution_dir / "full_scan_timeline.json").write_text(
        json.dumps(timeline), encoding="utf-8"
    )

    return handle


class TestStatusEngine:
    def test_get_status_no_projects(self, status_engine):
        engine, _, _ = status_engine
        result = engine.get_status()
        assert "error" in result

    def test_get_status_with_project(self, status_engine):
        engine, config, projects = status_engine
        handle = _create_project_with_findings(projects, "testcorp-test-project")
        result = engine.get_status(handle.slug)
        assert result["slug"] == handle.slug
        assert result["client"] == "TestCorp"
        assert result["project"] == "Test Project"
        assert result["target"] == "example.com"
        assert result["last_scan"] is not None
        assert result["total_findings"] > 0
        assert result["findings"]["critical"] == 1
        assert result["findings"]["high"] == 2
        assert result["findings"]["medium"] == 3
        assert result["findings"]["low"] == 4
        assert result["findings"]["info"] == 5

    def test_get_status_auto_select_single(self, status_engine):
        engine, config, projects = status_engine
        _create_project_with_findings(projects, "single-project")
        result = engine.get_status()
        assert "error" not in result
        assert result["slug"] is not None

    def test_get_status_project_not_found(self, status_engine):
        engine, _, _ = status_engine
        result = engine.get_status("nonexistent-slug")
        assert "error" in result or result is None

    def test_get_status_no_scan(self, status_engine):
        engine, config, projects = status_engine
        handle = projects.create_project(client="New", name="Project", domain="test.com")
        result = engine.get_status(handle.slug)
        assert result["slug"] == handle.slug
        assert result.get("last_scan") is None
        assert result["total_findings"] == 0

    def test_get_status_multiple_no_slug(self, status_engine):
        engine, config, projects = status_engine
        projects.create_project(client="A", name="Project A", domain="a.com")
        projects.create_project(client="B", name="Project B", domain="b.com")
        result = engine.get_status()
        assert "error" in result
        assert "projects" in result
