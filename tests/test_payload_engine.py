"""Tests for PayloadEngine (integration-level tests with mocks)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ghostmirror.models.payload_profile import PayloadCategory
from ghostmirror.modules.payloads.engine import PayloadEngine


@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    proj = tmp_path / "test_project"
    proj.mkdir()
    (proj / "findings").mkdir()
    (proj / "profiles").mkdir()
    (proj / "evidence").mkdir()
    (proj / "evidence" / "owasp").mkdir()
    (proj / "evidence" / "payloads").mkdir()
    return proj


@pytest.fixture()
def engine(project_dir: Path) -> PayloadEngine:
    return PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=True,
    )


def test_analyze_project_dry_run(engine: PayloadEngine) -> None:
    report = engine.analyze_project()
    assert report["dry_run"]
    assert report["total_payloads_registered"] > 0
    assert report["payloads_executed"] == 0
    assert report["findings_generated"] == 0


def test_analyze_project_with_category(engine: PayloadEngine) -> None:
    report = engine.analyze_project(category=PayloadCategory.XSS_REFLECTION)
    assert report["total_payloads_registered"] > 0
    categories = report["categories_tested"]
    for c in categories:
        assert c == PayloadCategory.XSS_REFLECTION.value


def test_analyze_project_saves_outputs(project_dir: Path) -> None:
    engine = PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=True,
    )
    engine.analyze_project()

    assert (project_dir / "findings" / "payload_findings.json").exists()
    assert (project_dir / "profiles" / "payload_profile.json").exists()
    assert (project_dir / "evidence" / "payloads" / "payload_results.json").exists()
    assert (project_dir / "evidence" / "payloads" / "sanitized_evidence.json").exists()


def test_payload_findings_content(project_dir: Path) -> None:
    engine = PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=True,
    )
    engine.analyze_project()
    findings_path = project_dir / "findings" / "payload_findings.json"
    with open(findings_path, "r") as f:
        findings = json.load(f)
    assert isinstance(findings, list)


def test_payload_profile_content(project_dir: Path) -> None:
    engine = PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=True,
    )
    engine.analyze_project()
    profile_path = project_dir / "profiles" / "payload_profile.json"
    with open(profile_path, "r") as f:
        profile = json.load(f)
    assert profile["target"] == "http://example.com"
    assert profile["dry_run"] is True


def test_execute_with_mocked_requests(project_dir: Path) -> None:
    engine = PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=False,
    )
    with patch.object(engine.executor, "_request") as mock_request:
        mock_request.return_value = (200, {"content-type": "text/html"}, "Hello World", 0.1)
        report = engine.analyze_project(category=PayloadCategory.XSS_REFLECTION)
        assert report["payloads_executed"] > 0


def test_execute_with_mocked_signal(project_dir: Path) -> None:
    engine = PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=False,
    )
    with patch.object(engine.executor, "_request") as mock_request:
        mock_request.side_effect = [
            (200, {}, "Baseline page", 0.1),
            (200, {}, "Probe with <script>alert(1)</script> reflected", 0.15),
        ]
        report = engine.analyze_project(category=PayloadCategory.XSS_REFLECTION)
        assert report["findings_generated"] > 0


def test_owasp_integration_loads_surfaces(project_dir: Path) -> None:
    forms_data = {
        "forms": [
            {
                "method": "GET",
                "inputs": [{"type": "text", "name": "search"}],
            }
        ]
    }
    enum_data = {"get_parameters": ["q", "url"]}
    with open(project_dir / "evidence" / "owasp" / "forms.json", "w") as f:
        json.dump(forms_data, f)
    with open(project_dir / "evidence" / "owasp" / "enumeration.json", "w") as f:
        json.dump(enum_data, f)

    engine = PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=True,
    )
    surfaces = engine._load_owasp_surfaces()
    assert len(surfaces) > 0
    assert any(s["parameter"] == "search" for s in surfaces)
    assert any(s["parameter"] == "q" for s in surfaces)


def test_owasp_integration_no_files(project_dir: Path) -> None:
    engine = PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=True,
    )
    surfaces = engine._load_owasp_surfaces()
    assert surfaces == []


def test_check_health() -> None:
    health = PayloadEngine.check_health(Path("."))
    assert "registry_valid" in health
    assert "safety_policy_valid" in health
    assert health["total_payloads_registered"] > 0


@pytest.mark.parametrize(
    "category,expected_executed",
    [
        (PayloadCategory.XSS_REFLECTION, 4),
        (PayloadCategory.SQL_ERROR_INDICATOR, 4),
        (PayloadCategory.OPEN_REDIRECT_INDICATOR, 2),
    ],
)
def test_category_payload_counts(
    project_dir: Path,
    category: PayloadCategory,
    expected_executed: int,
) -> None:
    engine = PayloadEngine(
        project_path=project_dir,
        target="http://example.com",
        dry_run=True,
    )
    report = engine.analyze_project(category=category)
    assert report["total_payloads_registered"] >= expected_executed
