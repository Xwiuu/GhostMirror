from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.models.hypothesis_report import HypothesisReport
from ghostmirror.modules.zero_day.engine import ZeroDayEngine
from ghostmirror.modules.zero_day.recommendations import ZeroDayRecommendations
from ghostmirror.modules.zero_day.findings_mapper import ZeroDayFindingsMapper
from ghostmirror.modules.zero_day.report_builder import ZeroDayReportBuilder


class TestZeroDayEngine:
    def test_init(self):
        engine = ZeroDayEngine()
        assert engine.anomaly_engine is not None
        assert engine.differential_engine is not None
        assert engine.hidden_functionality_engine is not None
        assert engine.business_logic_engine is not None
        assert engine.attack_chain_engine is not None
        assert engine.hypothesis_builder is not None
        assert engine.research_queue is not None
        assert engine.scoring_engine is not None
        assert engine.recommendation_engine is not None
        assert engine.findings_mapper is not None
        assert engine.report_builder is not None

    def test_analyze_project_no_target(self, tmp_path: Path):
        engine = ZeroDayEngine()
        report = engine.analyze_project(tmp_path)
        assert report.overall_score == 0
        assert report.risk_level == "INFO"

    def test_analyze_project_with_target_no_profiles(self, tmp_path: Path):
        tech_dir = tmp_path / "profiles"
        tech_dir.mkdir(parents=True, exist_ok=True)
        with open(tech_dir / "technology_profile.json", "w") as f:
            json.dump({"target": "https://example.com"}, f)

        engine = ZeroDayEngine()
        report = engine.analyze_project(tmp_path)
        assert isinstance(report, HypothesisReport)
        assert report.target == "https://example.com"

    def test_empty_report(self):
        engine = ZeroDayEngine()
        report = engine._empty_report()
        assert isinstance(report, HypothesisReport)
        assert report.overall_score == 0
        assert report.risk_level == "INFO"

    def test_collect_all_signals(self):
        engine = ZeroDayEngine()
        signals = engine._collect_all_signals(
            anomalies=[{"signals": [{"signal_type": "rare_endpoint", "source": "test"}]}],
            differential_signals=[{"signal_type": "differential_status", "source": "test"}],
            hidden_hypotheses=[{"signals": ["flag: isAdminOverride"]}],
            attack_chains=[],
            opportunities=[],
        )
        assert len(signals) == 3

    def test_save_json(self, tmp_path: Path):
        engine = ZeroDayEngine()
        p = tmp_path / "test.json"
        engine._save_json(p, {"key": "value"})
        assert p.exists()
        with open(p) as f:
            assert json.load(f) == {"key": "value"}

    def test_save_json_exception(self, tmp_path: Path):
        engine = ZeroDayEngine()
        engine._save_json(tmp_path / "test.json", {"key": "value"})

    def test_load_json_malformed(self, tmp_path: Path):
        engine = ZeroDayEngine()
        p = tmp_path / "bad.json"
        with open(p, "w") as f:
            f.write("{invalid}")
        assert engine._load_json(p) is None

    def test_save_json_write_error(self):
        engine = ZeroDayEngine()
        engine._save_json(Path("Z:/nonexistent/test.json"), {"key": "value"})

    def test_load_json_missing(self, tmp_path: Path):
        engine = ZeroDayEngine()
        assert engine._load_json(tmp_path / "nonexistent.json") is None

    def test_save_zero_day_findings(self, tmp_path: Path):
        engine = ZeroDayEngine()
        engine._save_zero_day_findings(tmp_path, [{"title": "Test finding"}])
        findings_file = tmp_path / "findings" / "zero_day.json"
        assert findings_file.exists()
        with open(findings_file) as f:
            data = json.load(f)
        assert len(data) == 1

    def test_save_zero_day_findings_empty(self, tmp_path: Path):
        engine = ZeroDayEngine()
        engine._save_zero_day_findings(tmp_path, [])
        assert not (tmp_path / "findings" / "zero_day.json").exists()

    def test_report_output_structure(self, tmp_path: Path):
        tech_dir = tmp_path / "profiles"
        tech_dir.mkdir(parents=True, exist_ok=True)
        with open(tech_dir / "technology_profile.json", "w") as f:
            json.dump({"target": "https://example.com"}, f)

        engine = ZeroDayEngine()
        report = engine.analyze_project(tmp_path)
        assert hasattr(report, "anomalies")
        assert hasattr(report, "attack_chains")
        assert hasattr(report, "hypotheses")
        assert hasattr(report, "opportunities")
        assert hasattr(report, "research_queue")
        assert hasattr(report, "overall_score")
        assert hasattr(report, "risk_level")


class TestZeroDayRecommendations:
    def test_generate_critical(self):
        r = ZeroDayRecommendations()
        recs = r.generate([], [], [], [], 80)
        assert len(recs) >= 1
        assert "CRITICAL" in recs[0]

    def test_generate_high(self):
        r = ZeroDayRecommendations()
        recs = r.generate([], [], [], [], 60)
        assert len(recs) >= 1

    def test_generate_low(self):
        r = ZeroDayRecommendations()
        recs = r.generate([], [], [], [], 10)
        assert len(recs) >= 1

    def test_generate_with_anomalies(self):
        r = ZeroDayRecommendations()
        recs = r.generate(
            anomalies=[{"severity": "HIGH"}, {"severity": "CRITICAL"}],
            attack_chains=[],
            hypotheses=[],
            opportunities=[],
            overall_score=50,
        )
        assert any("high-severity" in rec.lower() for rec in recs)

    def test_generate_with_attack_chains(self):
        r = ZeroDayRecommendations()
        recs = r.generate(
            anomalies=[],
            attack_chains=[{"title": "Test chain"}],
            hypotheses=[],
            opportunities=[],
            overall_score=30,
        )
        assert any("attack" in rec.lower() for rec in recs)

    def test_generate_with_bl_opportunities(self):
        r = ZeroDayRecommendations()
        recs = r.generate(
            anomalies=[],
            attack_chains=[],
            hypotheses=[],
            opportunities=[{"opportunity_type": "Business Logic Research"}],
            overall_score=30,
        )
        assert any("business logic" in rec.lower() for rec in recs)

    def test_generate_with_hidden_hypotheses(self):
        r = ZeroDayRecommendations()
        recs = r.generate(
            anomalies=[], attack_chains=[], hypotheses=[
                {"hypothesis_type": "Hidden Functionality Research"},
            ], opportunities=[], overall_score=30,
        )
        assert any("hidden" in rec.lower() for rec in recs)

    def test_generate_with_auth_hypotheses(self):
        r = ZeroDayRecommendations()
        recs = r.generate(
            anomalies=[], attack_chains=[], hypotheses=[
                {"hypothesis_type": "Authorization Research"},
            ], opportunities=[], overall_score=30,
        )
        assert any("authorization" in rec.lower() for rec in recs)


class TestZeroDayFindingsMapper:
    def test_map_to_findings_empty(self):
        m = ZeroDayFindingsMapper()
        result = m.map_to_findings([], [], [], [])
        assert result == []

    def test_map_to_findings_with_data(self):
        m = ZeroDayFindingsMapper()
        result = m.map_to_findings(
            anomalies=[{"title": "Anomaly 1", "description": "desc", "severity": "HIGH", "confidence": "MEDIUM", "score": 60, "endpoint": "/admin"}],
            attack_chains=[{"title": "Chain 1", "description": "desc", "severity": "CRITICAL", "confidence": "HIGH", "score": 90, "components": ["JWT"]}],
            hypotheses=[{"title": "Hyp 1", "reasoning": "reason", "impact": "HIGH", "confidence": "HIGH", "score": 80, "signals": ["flag1"]}],
            opportunities=[{"title": "Opp 1", "description": "desc", "priority": "MEDIUM", "confidence": "LOW", "score": 40, "signals": ["ep1"]}],
        )
        assert len(result) == 4
        assert all("score" in f for f in result)
        assert result[0]["score"] >= result[-1]["score"]

    def test_anomaly_to_finding(self):
        m = ZeroDayFindingsMapper()
        f = m._anomaly_to_finding({"title": "T", "description": "D", "severity": "HIGH", "confidence": "MEDIUM", "score": 60, "endpoint": "/admin"})
        assert f["category"] == "zero_day_anomaly"
        assert f["type"] == "Zero-Day Hypothesis / Anomaly"

    def test_chain_to_finding(self):
        m = ZeroDayFindingsMapper()
        f = m._chain_to_finding({"title": "T", "description": "D", "severity": "CRITICAL", "confidence": "HIGH", "score": 90, "components": ["JWT"]})
        assert f["category"] == "zero_day_attack_chain"

    def test_hypothesis_to_finding(self):
        m = ZeroDayFindingsMapper()
        f = m._hypothesis_to_finding({"title": "T", "reasoning": "R", "impact": "HIGH", "confidence": "HIGH", "score": 80, "signals": ["s1"]})
        assert f["category"] == "zero_day_hypothesis"
        assert f["type"] == "Zero-Day Hypothesis"

    def test_opportunity_to_finding(self):
        m = ZeroDayFindingsMapper()
        f = m._opportunity_to_finding({"title": "T", "description": "D", "priority": "MEDIUM", "confidence": "LOW", "score": 40, "signals": ["e1"]})
        assert f["category"] == "zero_day_opportunity"
        assert f["type"] == "Zero-Day Hypothesis / Research Opportunity"


class TestZeroDayReportBuilder:
    def test_build(self):
        builder = ZeroDayReportBuilder()
        report = builder.build(
            target="https://example.com",
            anomalies=[{"title": "A1"}],
            differential_signals=[{"title": "D1"}],
            hidden_hypotheses=[{"title": "HH1"}],
            business_opportunities=[{"title": "BO1"}],
            attack_chains=[{"title": "AC1"}],
            hypotheses=[{"title": "H1"}],
            opportunities=[{"title": "O1"}],
            research_queue=[{"title": "RQ1"}],
            recommendations=["Test recommendation"],
            findings=[{"title": "F1"}],
            overall_score=75,
            risk_level="HIGH",
        )
        assert report.target == "https://example.com"
        assert report.overall_score == 75
        assert report.risk_level == "HIGH"
        assert len(report.anomalies) == 1
        assert len(report.attack_chains) == 1
        assert len(report.hypotheses) == 1
        assert len(report.opportunities) == 1
        assert len(report.research_queue) == 1
        assert report.total_signals == 2
        assert report.total_hypotheses == 2
        assert report.total_attack_chains == 1
