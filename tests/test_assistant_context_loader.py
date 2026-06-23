"""Tests for Assistant Context Loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.pentester_assistant.context_loader import ContextLoader


@pytest.fixture()
def project_dir(tmp_path: Path) -> Path:
    (tmp_path / "profiles").mkdir()
    (tmp_path / "findings").mkdir()
    return tmp_path


class TestContextLoader:
    def test_empty_project(self, project_dir: Path):
        loader = ContextLoader()
        ctx = loader.load(project_dir, "target.com")
        assert ctx.target == "target.com"
        assert ctx.project == project_dir.name
        assert ctx.total_sources_loaded == 0
        assert ctx.top_findings == []

    def test_loads_enriched_findings(self, project_dir: Path):
        ef_path = project_dir / "profiles" / "finding_intelligence_report.json"
        ef_path.write_text(json.dumps({
            "enriched_findings": [
                {"title": "XSS", "severity": "HIGH", "priority": "P1", "confidence": "HIGH"},
                {"title": "Info Leak", "severity": "LOW", "priority": "P4", "confidence": "LOW"},
            ],
            "quick_wins": [{"title": "Quick Win", "severity": "MEDIUM"}],
        }), encoding="utf-8")

        loader = ContextLoader()
        ctx = loader.load(project_dir)
        assert ctx.total_sources_loaded >= 1
        assert len(ctx.top_findings) == 2
        assert len(ctx.quick_wins) == 1

    def test_loads_attack_chains(self, project_dir: Path):
        ac_dir = project_dir / "profiles" / "attack_chain"
        ac_dir.mkdir()
        (ac_dir / "attack_chain_report.json").write_text(json.dumps({
            "top_chains": [{"title": "Chain 1", "score": 80}],
            "total_chains": 1,
        }), encoding="utf-8")

        loader = ContextLoader()
        ctx = loader.load(project_dir)
        assert len(ctx.top_attack_chains) == 1
        assert ctx.top_attack_chains[0]["title"] == "Chain 1"

    def test_loads_zero_day_hypotheses(self, project_dir: Path):
        zd_dir = project_dir / "profiles" / "zero_day"
        zd_dir.mkdir()
        (zd_dir / "hypotheses.json").write_text(json.dumps([
            {"title": "Hypothesis 1", "score": 70},
        ]), encoding="utf-8")

        loader = ContextLoader()
        ctx = loader.load(project_dir)
        assert len(ctx.top_hypotheses) == 1

    def test_loads_api_risks(self, project_dir: Path):
        api_dir = project_dir / "profiles" / "api_security"
        api_dir.mkdir()
        (api_dir / "jwt_profile.json").write_text(json.dumps({
            "detected": True,
            "has_none_alg_indicator": True,
            "has_exp": False,
        }), encoding="utf-8")
        (api_dir / "bola_indicators.json").write_text(json.dumps([
            {"confidence": "HIGH", "endpoint": "/api/users/{id}"},
        ]), encoding="utf-8")

        loader = ContextLoader()
        ctx = loader.load(project_dir)
        assert len(ctx.top_api_risks) >= 2

    def test_loads_vulnerability_intelligence(self, project_dir: Path):
        vi_dir = project_dir / "profiles" / "vulnerability_intelligence"
        vi_dir.mkdir()
        (vi_dir / "vulnerability_intelligence_report.json").write_text(json.dumps({
            "priorities": [{"cve": "CVE-2024-1234", "risk_score": 90}],
        }), encoding="utf-8")

        loader = ContextLoader()
        ctx = loader.load(project_dir)
        assert len(ctx.top_cves) == 1

    def test_missing_files_handled(self, project_dir: Path):
        loader = ContextLoader()
        ctx = loader.load(project_dir)
        assert ctx.total_sources_loaded == 0
        assert ctx.top_findings == []
        assert ctx.top_cves == []

    def test_scanner_findings_loaded(self, project_dir: Path):
        (project_dir / "findings" / "headers.json").write_text(json.dumps({
            "findings": [
                {"title": "Missing HSTS", "severity": "HIGH"},
                {"title": "Info Leak", "severity": "INFO"},
            ],
        }), encoding="utf-8")

        loader = ContextLoader()
        ctx = loader.load(project_dir)
        assert ctx.total_sources_loaded >= 1
        high_risks = [r for r in ctx.business_risks if r.get("severity", "").upper() == "HIGH"]
        assert len(high_risks) == 1
