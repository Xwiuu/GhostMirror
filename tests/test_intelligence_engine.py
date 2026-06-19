"""Tests for the full Intelligence Engine integration."""
from __future__ import annotations
import json
from pathlib import Path
import pytest
from ghostmirror.models.attack_path import AttackPath
from ghostmirror.models.attack_surface_profile import AttackSurfaceProfile
from ghostmirror.models.intelligence_report import IntelligenceReport, PentestRecommendation, RiskMatrix, RiskMatrixEntry
from ghostmirror.modules.intelligence.engine import IntelligenceEngine
from ghostmirror.modules.intelligence.executive_summary import ExecutiveSummaryGenerator
from ghostmirror.modules.intelligence.recommendations import RecommendationEngine
from ghostmirror.modules.intelligence.risk_matrix import RiskMatrixGenerator


class TestIntelligenceReportModels:
    def test_risk_matrix_entry(self) -> None:
        entry = RiskMatrixEntry(category="Likelihood", score=65, level="High", description="Test")
        assert entry.category == "Likelihood"
        assert entry.score == 65
        assert entry.level == "High"

    def test_risk_matrix(self) -> None:
        matrix = RiskMatrix(
            likelihood=RiskMatrixEntry(category="Likelihood", score=40, level="Medium"),
            impact=RiskMatrixEntry(category="Impact", score=70, level="High"),
            overall_level="High",
        )
        assert matrix.likelihood.level == "Medium"
        assert matrix.impact.score == 70
        assert matrix.overall_level == "High"

    def test_pentest_recommendation(self) -> None:
        rec = PentestRecommendation(
            assessment_type="Web App Pentest",
            priority="Critical",
            justification="Critical findings detected",
            findings_reference=["CVE-2021-1234"],
        )
        assert rec.assessment_type == "Web App Pentest"
        assert rec.priority == "Critical"

    def test_intelligence_report(self) -> None:
        report = IntelligenceReport(
            target="test.com",
            overall_security_score=65,
            overall_attack_surface_score=70,
            overall_risk_score=60,
            executive_summary="Test summary",
        )
        assert report.target == "test.com"
        assert report.overall_security_score == 65
        assert report.executive_summary == "Test summary"


class TestRiskMatrixGenerator:
    def test_low_risk(self) -> None:
        matrix = RiskMatrixGenerator.generate(
            attack_surface_score=10, critical_findings=0, high_findings=0, medium_findings=0,
            total_findings=0, cve_count=0,
        )
        assert matrix.likelihood.level == "Low"
        assert matrix.business_risk.level in ("Low", "Medium")

    def test_high_risk(self) -> None:
        matrix = RiskMatrixGenerator.generate(
            attack_surface_score=80, critical_findings=3, high_findings=5, medium_findings=10,
            total_findings=20, cve_count=15, exploit_available=True, kev_count=3, open_ports_count=10,
        )
        assert matrix.business_risk.level in ("High", "Critical")


class TestRecommendationEngine:
    def test_critical_findings(self) -> None:
        recs = RecommendationEngine.generate(
            cms_list=["WordPress"], databases=[], frameworks=["Laravel"],
            open_ports=[80, 443], critical_findings=2, high_findings=3, medium_findings=5,
            cve_count=10, exploit_available=True, waf_detected=False,
            dns_issues=["SPF", "DMARC"], technologies_count=8,
        )
        types = [r.assessment_type for r in recs]
        assert "Web Application Penetration Test" in types
        assert "Email Security Assessment" in types
        critical = [r for r in recs if r.priority == "Critical"]
        assert len(critical) >= 1

    def test_low_findings(self) -> None:
        recs = RecommendationEngine.generate(
            cms_list=[], databases=[], frameworks=[], open_ports=[],
            critical_findings=0, high_findings=0, medium_findings=0, cve_count=0,
            exploit_available=False, waf_detected=True, dns_issues=[], technologies_count=2,
        )
        assert len(recs) >= 1


class TestExecutiveSummaryGenerator:
    def test_generate_summary(self) -> None:
        summary = ExecutiveSummaryGenerator.generate(
            target="test.com",
            technologies=["nginx", "php", "wordpress"],
            cms_list=["WordPress"], frameworks=["Laravel"], databases=["MySQL"],
            waf_vendor=None, cdn_vendor="Cloudflare", hosting_provider="AWS",
            dns_findings=[{"record_type": "SPF", "status": "MISSING", "details": "Not found"}],
            open_ports=[80, 443, 3306],
            critical_findings=1, high_findings=3, medium_findings=5, low_findings=2,
            total_findings=11, cve_count=5, attack_surface_score=65, risk_score=70,
            risk_level="HIGH", exploit_available=True, kev_count=2,
        )
        assert "test.com" in summary
        assert "HIGH" in summary

    def test_minimal_summary(self) -> None:
        summary = ExecutiveSummaryGenerator.generate(
            target="test.com", technologies=[], cms_list=[], frameworks=[], databases=[],
            waf_vendor=None, cdn_vendor=None, hosting_provider=None, dns_findings=[],
            open_ports=[], critical_findings=0, high_findings=0, medium_findings=0,
            low_findings=0, total_findings=0, cve_count=0, attack_surface_score=5,
            risk_score=5, risk_level="LOW", exploit_available=False, kev_count=0,
        )
        assert "test.com" in summary


class TestIntelligenceEngine:
    def test_engine_no_project_data(self, tmp_path: Path) -> None:
        engine = IntelligenceEngine()
        (tmp_path / "profiles").mkdir()
        (tmp_path / "findings").mkdir()
        report = engine.analyze_project(tmp_path)
        assert isinstance(report, IntelligenceReport)
        assert report.target is not None
        assert 0 <= report.overall_security_score <= 100
        assert 0 <= report.overall_attack_surface_score <= 100
        assert 0 <= report.overall_risk_score <= 100

    def test_engine_saves_outputs(self, tmp_path: Path) -> None:
        profiles_dir = tmp_path / "profiles"
        findings_dir = tmp_path / "findings"
        profiles_dir.mkdir()
        findings_dir.mkdir()
        tech_data = {"target": "test.com", "technologies": [{"name": "Nginx", "category": "WEB SERVER", "version": "1.20", "confidence": 1.0, "source": "test"}]}
        with open(profiles_dir / "technology_profile.json", "w") as f:
            json.dump(tech_data, f)
        nmap_data = {"open_ports": [80, 443], "services": ["http", "https"]}
        with open(findings_dir / "nmap.json", "w") as f:
            json.dump(nmap_data, f)
        engine = IntelligenceEngine()
        report = engine.analyze_project(tmp_path)
        assert (profiles_dir / "intelligence_report.json").exists()
        assert (profiles_dir / "risk_matrix.json").exists()
        assert (profiles_dir / "attack_paths.json").exists()
        assert (profiles_dir / "executive_summary.json").exists()
        assert (profiles_dir / "waf_profile.json").exists()
        assert (profiles_dir / "cdn_profile.json").exists()
        assert (profiles_dir / "hosting_profile.json").exists()
        assert (profiles_dir / "dns_profile.json").exists()
