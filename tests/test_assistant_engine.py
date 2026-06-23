"""Tests for Pentester Assistant Engine — full integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.pentester_assistant.engine import PentesterAssistantEngine


@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    (tmp_path / "profiles").mkdir()
    (tmp_path / "findings").mkdir()
    return tmp_path


@pytest.fixture()
def project_with_data(project_dir: Path) -> Path:
    """Project with enriched findings and attack chains."""
    # Enriched findings
    ef_path = project_dir / "profiles" / "finding_intelligence_report.json"
    ef_path.write_text(json.dumps({
        "enriched_findings": [
            {"title": "BOLA in API", "severity": "HIGH", "priority": "P1", "confidence": "HIGH",
             "category": "api", "evidence": "/api/users/{id}"},
            {"title": "Missing HSTS", "severity": "MEDIUM", "priority": "P3", "confidence": "MEDIUM",
             "category": "header"},
        ],
        "quick_wins": [{"title": "Quick", "severity": "MEDIUM"}],
    }), encoding="utf-8")

    # Attack chains
    ac_dir = project_dir / "profiles" / "attack_chain"
    ac_dir.mkdir()
    (ac_dir / "attack_chain_report.json").write_text(json.dumps({
        "top_chains": [{"title": "JWT + Admin API", "score": 85}],
        "total_chains": 1,
    }), encoding="utf-8")
    (ac_dir / "signals.json").write_text(json.dumps([
        {"signal_type": "JWT_DETECTED", "asset": "api", "severity": "HIGH", "confidence": 0.8},
    ]), encoding="utf-8")

    # Zero-day hypotheses
    zd_dir = project_dir / "profiles" / "zero_day"
    zd_dir.mkdir()
    (zd_dir / "hypotheses.json").write_text(json.dumps([
        {"title": "Hidden endpoint", "score": 65},
    ]), encoding="utf-8")

    # API security
    api_dir = project_dir / "profiles" / "api_security"
    api_dir.mkdir()
    (api_dir / "jwt_profile.json").write_text(json.dumps({
        "detected": True, "has_none_alg_indicator": False, "has_exp": True,
    }), encoding="utf-8")

    return project_dir


class TestPentesterAssistantEngine:
    def test_empty_project(self, project_dir: Path):
        engine = PentesterAssistantEngine()
        report = engine.analyze_project(project_dir, "target.com")
        assert report.target == "target.com"
        assert report.total_priorities == 0
        assert report.safety_disclaimer != ""

    def test_full_run(self, project_with_data: Path):
        engine = PentesterAssistantEngine()
        report = engine.analyze_project(project_with_data, "target.com")
        assert report.total_priorities > 0
        assert report.total_tasks > 0
        assert report.total_checklists > 0
        assert report.total_questions > 0
        assert report.risk_narrative != ""
        assert report.executive_summary != ""

    def test_saves_profiles(self, project_with_data: Path):
        engine = PentesterAssistantEngine()
        engine.analyze_project(project_with_data)

        assert (project_with_data / "profiles" / "assistant" / "assistant_report.json").exists()
        assert (project_with_data / "profiles" / "assistant" / "assistant_priorities.json").exists()
        assert (project_with_data / "profiles" / "assistant" / "assistant_context.json").exists()

    def test_saves_reports(self, project_with_data: Path):
        engine = PentesterAssistantEngine()
        engine.analyze_project(project_with_data)

        assert (project_with_data / "reports" / "assistant_report.md").exists()
        assert (project_with_data / "reports" / "assistant_report.html").exists()

    def test_saves_findings(self, project_with_data: Path):
        engine = PentesterAssistantEngine()
        engine.analyze_project(project_with_data)

        findings_path = project_with_data / "findings" / "assistant_findings.json"
        assert findings_path.exists()
        with open(findings_path, encoding="utf-8") as f:
            findings = json.load(f)
        assert len(findings) > 0
        assert findings[0]["category"] == "pentest_guidance"

    def test_safety_disclaimer_in_report(self, project_with_data: Path):
        engine = PentesterAssistantEngine()
        report = engine.analyze_project(project_with_data)
        assert "authorized manual review" in report.safety_disclaimer

    def test_zero_day_notes(self, project_with_data: Path):
        engine = PentesterAssistantEngine()
        report = engine.analyze_project(project_with_data)
        assert len(report.zero_day_notes) > 0
        for note in report.zero_day_notes:
            assert "research opportunity" in note["status"].lower()

    def test_hackerone_guidance(self, project_with_data: Path):
        engine = PentesterAssistantEngine()
        report = engine.analyze_project(project_with_data)
        if report.hackerone_guidance:
            for g in report.hackerone_guidance:
                assert "validation_steps" in g
                assert "confidence_assessment" in g
