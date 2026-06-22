from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ghostmirror.models.attack_chain_report import AttackChainReport
from ghostmirror.modules.attack_chain.engine import AttackChainEngine


class TestAttackChainEngine:
    @pytest.fixture
    def engine(self) -> AttackChainEngine:
        return AttackChainEngine()

    @pytest.fixture
    def project_path(self, tmp_path: Path) -> Path:
        base = tmp_path / "project"
        base.mkdir(parents=True)
        p = base / "profiles"
        p.mkdir()
        f = base / "findings"
        f.mkdir()
        # Write minimal tech profile
        with open(p / "technology_profile.json", "w", encoding="utf-8") as fh:
            json.dump({"target": "test.com"}, fh)
        return base

    def _write_web_indicator(self, path: Path):
        wi = path / "profiles" / "web_intelligence"
        wi.mkdir(parents=True, exist_ok=True)
        with open(wi / "web_indicators.json", "w", encoding="utf-8") as f:
            json.dump([{"id": "xss1", "indicator_type": "xss", "asset": "test.com",
                        "severity": "high", "confidence": 0.8, "tags": ["xss"]}], f)

    def test_analyze_no_signals(self, engine: AttackChainEngine, project_path: Path):
        report = engine.analyze_project(project_path)
        assert isinstance(report, AttackChainReport)
        assert report.total_signals == 0

    def test_analyze_with_signals(self, engine: AttackChainEngine, project_path: Path):
        self._write_web_indicator(project_path)
        report = engine.analyze_project(project_path)
        assert report.total_signals >= 1
        assert report.project == project_path.name

    def test_analyze_creates_output_files(self, engine: AttackChainEngine, project_path: Path):
        self._write_web_indicator(project_path)
        engine.analyze_project(project_path)
        ac_dir = project_path / "profiles" / "attack_chain"
        assert (ac_dir / "signals.json").exists()
        assert (ac_dir / "attack_graph.json").exists()
        assert (ac_dir / "chains.json").exists()
        assert (ac_dir / "attack_chain_priorities.json").exists()
        assert (ac_dir / "attack_chain_report.json").exists()

    def test_analyze_with_rich_signals(self, engine: AttackChainEngine, project_path: Path):
        self._write_web_indicator(project_path)
        api_dir = project_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "jwt_profile.json", "w", encoding="utf-8") as f:
            json.dump({"detected": True, "confidence": 0.9}, f)
        with open(api_dir / "bola_indicators.json", "w", encoding="utf-8") as f:
            json.dump([{"id": "b1", "asset": "api", "endpoint": "/users/1",
                        "confidence": 0.7}], f)
        report = engine.analyze_project(project_path)
        assert report.total_signals >= 3
        assert report.total_chains >= 1

    def test_analyze_findings_saved(self, engine: AttackChainEngine, project_path: Path):
        self._write_web_indicator(project_path)
        engine.analyze_project(project_path)
        findings_path = project_path / "findings" / "attack_chain.json"
        assert findings_path.exists()

    def test_analyze_report_content(self, engine: AttackChainEngine, project_path: Path):
        self._write_web_indicator(project_path)
        report = engine.analyze_project(project_path)
        assert report.target == "test.com"
        assert report.overall_score >= 0
        assert report.risk_level in ("low", "medium", "high", "critical")

    def test_analyze_no_tech_profile(self, engine: AttackChainEngine, tmp_path: Path):
        base = tmp_path / "empty"
        base.mkdir(parents=True)
        prof = base / "profiles"
        prof.mkdir()
        find = base / "findings"
        find.mkdir()
        report = engine.analyze_project(base)
        assert isinstance(report, AttackChainReport)
        assert report.target == base.name
