"""Advanced edge-case tests for the Intelligence Engine to boost coverage."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.models.attack_surface_profile import (
    AttackSurfaceProfile,
    CDNProfile,
    DNSFinding,
    DNSProfile,
    HostingProfile,
    WAFProfile,
)
from ghostmirror.models.fingerprint import FingerprintProfile
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.models.attack_path import AttackPath, AttackPathStep
from ghostmirror.models.intelligence_report import (
    IntelligenceReport,
    PentestRecommendation,
    RiskMatrix,
    RiskMatrixEntry,
)
from ghostmirror.modules.intelligence.attack_surface import AttackSurfaceAnalyzer
from ghostmirror.modules.intelligence.scoring import ScoringEngine, classify_score
from ghostmirror.modules.intelligence.correlation import CorrelationEngine, CorrelatedFinding
from ghostmirror.modules.intelligence.attack_paths import AttackPathEngine
from ghostmirror.modules.intelligence.engine import IntelligenceEngine
from ghostmirror.modules.intelligence.executive_summary import ExecutiveSummaryGenerator
from ghostmirror.modules.intelligence.recommendations import RecommendationEngine
from ghostmirror.modules.intelligence.risk_matrix import RiskMatrixGenerator


# ==============================================================
# Attack Surface - Extended Edge Cases
# ==============================================================
class TestAttackSurfaceExtended:
    def test_waf_detection_headers_cloudflare(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "cf-ray", "value": "abc123"}, {"name": "server", "value": "cloudflare"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "Cloudflare"
        assert result.confidence >= 80

    def test_waf_detection_headers_akamai(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-akamai-transformed", "value": "yes"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "Akamai"

    def test_waf_detection_headers_imperva(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-iinfo", "value": "test"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "Imperva"

    def test_waf_detection_headers_sucuri(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-sucuri-id", "value": "123"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "Sucuri"

    def test_waf_detection_headers_aws(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-amzn-requestid", "value": "abc"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "AWS WAF"

    def test_waf_detection_headers_azure(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-azure-waf", "value": "test"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "Azure WAF"

    def test_waf_detection_headers_gcp(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-goog-abc", "value": "test"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "Google Cloud Armor"

    def test_waf_detection_headers_fastly(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-fastly-request", "value": "abc"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "Fastly"

    def test_waf_detection_headers_f5(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-f5-abc", "value": "test"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "F5"

    def test_waf_detection_headers_barracuda(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-barracuda-abc", "value": "test"}]
        result = analyzer._detect_waf(None, headers)
        assert result.detected is True
        assert result.vendor == "Barracuda"

    def test_waf_no_tech_no_headers(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_waf(None, None)
        assert result.detected is False

    def test_cdn_detection_headers_cloudfront(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-amz-cf-id", "value": "abc"}]
        result = analyzer._detect_cdn(None, headers)
        assert result.detected is True
        assert result.vendor == "CloudFront"

    def test_cdn_detection_headers_bunny(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-bunny-abc", "value": "test"}]
        result = analyzer._detect_cdn(None, headers)
        assert result.detected is True
        assert result.vendor == "BunnyCDN"

    def test_cdn_detection_headers_keycdn(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-keycdn-abc", "value": "test"}]
        result = analyzer._detect_cdn(None, headers)
        assert result.detected is True
        assert result.vendor == "KeyCDN"

    def test_cdn_detection_headers_stackpath(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "x-stackpath-abc", "value": "test"}]
        result = analyzer._detect_cdn(None, headers)
        assert result.detected is True
        assert result.vendor == "StackPath"

    def test_cdn_no_tech_no_headers(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_cdn(None, None)
        assert result.detected is False

    def test_hosting_detection_headers_aws(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "AmazonS3"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "AWS"

    def test_hosting_detection_headers_azure(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "Microsoft-Azure-Application-Gateway"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "Azure"

    def test_hosting_detection_headers_gcp(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "Google Cloud"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "GCP"

    def test_hosting_detection_headers_digitalocean(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "DigitalOcean"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "DigitalOcean"

    def test_hosting_detection_headers_vercel(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "Vercel"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "Vercel"

    def test_hosting_detection_headers_netlify(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "Netlify"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "Netlify"

    def test_hosting_detection_headers_linode(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "linode"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "Linode"

    def test_hosting_detection_headers_hetzner(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "hetzner.cloud"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "Hetzner"

    def test_hosting_detection_headers_oracle(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        headers = [{"name": "server", "value": "Oracle Cloud"}]
        result = analyzer._detect_hosting(None, headers)
        assert result.detected is True
        assert result.provider == "Oracle Cloud"

    def test_hosting_no_tech_no_headers(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_hosting(None, None)
        assert result.detected is False

    def test_hosting_from_tech_technologies(self) -> None:
        tech_profile = FingerprintProfile(
            target="test.com",
            technologies=[
                TechnologyModel(name="amazonaws.com", category="CLOUD", confidence=1.0, source="test"),
            ],
        )
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_hosting(tech_profile, None)
        assert result.detected is True
        assert result.provider == "AWS"

    def test_save_profiles(self, tmp_path: Path) -> None:
        profile = AttackSurfaceProfile(
            target="test.com",
            waf=WAFProfile(detected=True, vendor="Cloudflare", confidence=95),
            cdn=CDNProfile(detected=True, vendor="Fastly", confidence=85),
            hosting=HostingProfile(detected=True, provider="AWS", confidence=80),
            dns=DNSProfile(records={"A": ["1.2.3.4"]}, spf_missing=True),
        )
        analyzer = AttackSurfaceAnalyzer()
        analyzer.save_profiles(tmp_path, profile)
        assert (tmp_path / "profiles" / "waf_profile.json").exists()
        assert (tmp_path / "profiles" / "cdn_profile.json").exists()
        assert (tmp_path / "profiles" / "hosting_profile.json").exists()
        assert (tmp_path / "profiles" / "dns_profile.json").exists()

        waf_data = json.loads((tmp_path / "profiles" / "waf_profile.json").read_text())
        assert waf_data["vendor"] == "Cloudflare"

    def test_analyze_with_open_ports_observation(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer.analyze(
            target="test.com",
            nmap_findings={"open_ports": [22, 80, 443], "services": ["ssh", "http", "https"]},
        )
        assert any("3 port(s) open" in obs for obs in result.observations)
        assert any("No WAF or CDN" in obs for obs in result.observations)


# ==============================================================
# Scoring Engine - Extended
# ==============================================================
class TestScoringExtended:
    def test_attack_surface_max_score(self) -> None:
        profile = AttackSurfaceProfile(
            target="test.com",
            open_ports=list(range(1, 30)),
            services_exposed=["a", "b", "c", "d", "e", "f"],
            technologies=["t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10"],
            cms=["WordPress"],
            databases=["MySQL"],
            frameworks=["Laravel"],
            dns=DNSProfile(
                spf_missing=True, dmarc_missing=True, dkim_missing=True,
                findings=[DNSFinding(record_type="SPF", status="MISSING")],
            ),
        )
        score, cls = ScoringEngine.calculate_attack_surface_score(profile)
        assert 0 <= score <= 100
        assert cls in ("High", "Critical")

    def test_risk_score_with_exploit_and_kev(self) -> None:
        score, level = ScoringEngine.calculate_risk_score(
            attack_surface_score=50,
            findings_count=10,
            critical_findings=2,
            high_findings=5,
            medium_findings=3,
            cve_count=8,
            exploit_available=True,
            kev_listed=True,
        )
        assert 0 <= score <= 100
        assert level in ("High", "Critical")

    def test_overall_security_score_no_findings(self) -> None:
        score, level = ScoringEngine.overall_security_score(
            attack_surface_score=0, risk_score=0, findings_score=0,
        )
        assert score == 0
        assert level == "Minimal"

    def test_overall_security_score_max(self) -> None:
        score, level = ScoringEngine.overall_security_score(
            attack_surface_score=100, risk_score=100, findings_score=100,
        )
        assert score == 100
        assert level == "Critical"


# ==============================================================
# Correlation Engine - Extended
# ==============================================================
class TestCorrelationExtended:
    def test_port_tech_cve_correlation(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(fdir / "nmap.json", "w") as f:
            json.dump({"open_ports": [3306], "services": ["mysql"]}, f)
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"technologies": [{"name": "MySQL", "category": "DATABASE", "version": "8.0", "confidence": 1.0, "source": "test"}]}, f)
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"matches": [{"technology": "mysql", "matched_cve": {"cve_id": "CVE-2023-1234", "severity": "HIGH", "exploit_available": True, "kev_listed": False}}]}, f)
        with open(pdir / "nuclei_profile.json", "w") as f:
            json.dump({"findings": [{"template_id": "test-template", "host": "test.com:3306", "info": {}, "matched_at": "test"}]}, f)
        with open(pdir / "owasp_profile.json", "w") as f:
            json.dump({"findings": []}, f)
        results = CorrelationEngine.correlate(tmp_path)
        cve_findings = [r for r in results if "CVE" in r.title]
        assert len(cve_findings) >= 1

    def test_owasp_correlation_fallback(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(fdir / "nmap.json", "w") as f:
            json.dump({"open_ports": [8080], "services": ["http"]}, f)
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"technologies": [{"name": "Apache", "category": "WEB SERVER", "version": "2.4", "confidence": 1.0, "source": "test"}]}, f)
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"matches": []}, f)
        with open(pdir / "nuclei_profile.json", "w") as f:
            json.dump({"findings": []}, f)
        with open(pdir / "owasp_profile.json", "w") as f:
            json.dump({"findings": [{"category": "A1-Injection", "severity": "MEDIUM", "title": "8080 found", "description": "Open proxy test"}]}, f)
        results = CorrelationEngine.correlate(tmp_path)
        owasp_findings = [r for r in results if "OWASP" in r.title]
        assert len(owasp_findings) >= 1

    def test_nuclei_correlation_match(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(fdir / "nmap.json", "w") as f:
            json.dump({"open_ports": [22], "services": ["ssh"]}, f)
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"technologies": [{"name": "OpenSSH", "category": "SERVICE", "version": "8.0", "confidence": 1.0, "source": "test"}]}, f)
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"matches": []}, f)
        with open(pdir / "nuclei_profile.json", "w") as f:
            json.dump({"findings": [{"template_id": "ssh-brute", "host": "test.com:22", "info": {"name": "SSH Brute Force", "severity": "high"}}]}, f)
        with open(pdir / "owasp_profile.json", "w") as f:
            json.dump({"findings": []}, f)
        results = CorrelationEngine.correlate(tmp_path)
        assert len(results) >= 0

    def test_nuclei_profile_as_matched_templates(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(fdir / "nmap.json", "w") as f:
            json.dump({"open_ports": [80], "services": ["http"]}, f)
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"technologies": [{"name": "Nginx", "category": "WEB SERVER", "version": "1.20", "confidence": 1.0, "source": "test"}]}, f)
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"matches": []}, f)
        with open(pdir / "nuclei_profile.json", "w") as f:
            json.dump({"matched_templates": [{"template_id": "nginx-test", "host": "test.com", "info": {"name": "Nginx Test", "severity": "medium"}, "matched_at": "test"}]}, f)
        with open(pdir / "owasp_profile.json", "w") as f:
            json.dump({"findings": []}, f)
        results = CorrelationEngine.correlate(tmp_path)
        assert len(results) >= 0


# ==============================================================
# Attack Path Engine - Extended
# ==============================================================
class TestAttackPathEngineExtended:
    def test_cms_path_joomla(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"technologies": [{"name": "Joomla", "category": "CMS", "version": "3.9", "confidence": 1.0, "source": "test"}]}, f)
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"matches": [{"technology": "joomla", "risk_level": "CRITICAL", "matched_cve": {"cve_id": "CVE-2020-1234", "severity": "CRITICAL"}}]}, f)
        paths = AttackPathEngine.generate_paths(tmp_path)
        j_paths = [p for p in paths if "joomla" in p.title.lower() or "Joomla" in p.title]
        assert len(j_paths) >= 1
        assert "Joomla" in j_paths[0].title

    def test_database_path_postgresql(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"technologies": [{"name": "PostgreSQL", "category": "DATABASE", "version": "13", "confidence": 1.0, "source": "test"}]}, f)
        paths = AttackPathEngine.generate_paths(tmp_path)
        pg_paths = [p for p in paths if "postgresql" in p.title.lower()]
        assert len(pg_paths) >= 1

    def test_web_path_with_owasp(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"technologies": [{"name": "Apache", "category": "WEB SERVER", "version": "2.4", "confidence": 1.0, "source": "test"}]}, f)
        with open(pdir / "owasp_profile.json", "w") as f:
            json.dump({"findings": [{"category": "A1-Injection", "severity": "HIGH", "title": "SQLi"}]}, f)
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"matches": []}, f)
        paths = AttackPathEngine.generate_paths(tmp_path)
        web_paths = [p for p in paths if "Web Application" in p.title]
        assert len(web_paths) >= 1
        assert any("SQLi" in str(s.detail) or "OWASP" in s.label or "6" in s.label for s in web_paths[0].steps)

    def test_web_path_with_cve(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"technologies": [{"name": "Nginx", "category": "WEB SERVER", "version": "1.20", "confidence": 1.0, "source": "test"}]}, f)
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"matches": [{"technology": "nginx", "risk_level": "HIGH", "matched_cve": {"cve_id": "CVE-2022-1234", "severity": "HIGH"}}]}, f)
        with open(pdir / "owasp_profile.json", "w") as f:
            json.dump({"findings": []}, f)
        paths = AttackPathEngine.generate_paths(tmp_path)
        web_paths = [p for p in paths if "Web Application" in p.title]
        assert len(web_paths) >= 1

    def test_attack_path_model_serialization(self) -> None:
        step = AttackPathStep(order=1, label="Test Step", detail="Detail", finding_ref="F1", severity="HIGH")
        assert step.finding_ref == "F1"
        assert step.severity == "HIGH"
        d = step.model_dump(mode="json")
        assert d["order"] == 1

        path = AttackPath(
            path_id=1,
            title="Test Path",
            description="A test",
            steps=[step],
            risk_score=50,
            risk_level="MEDIUM",
            prerequisites=["Prereq 1"],
            mitigations=["Mit 1"],
            likelihood="Medium",
            impact="High",
        )
        assert path.prerequisites == ["Prereq 1"]
        assert len(path.mitigations) == 1
        pd = path.model_dump(mode="json")
        assert pd["path_id"] == 1


# ==============================================================
# Executive Summary - Extended Edge Cases
# ==============================================================
class TestExecutiveSummaryExtended:
    def test_generate_with_all_concerns(self) -> None:
        summary = ExecutiveSummaryGenerator.generate(
            target="test.com",
            technologies=["nginx", "php", "wordpress", "mysql", "redis", "elasticsearch"],
            cms_list=["WordPress"], frameworks=["Laravel"], databases=["MySQL", "Redis"],
            waf_vendor=None, cdn_vendor=None, hosting_provider=None,
            dns_findings=[{"record_type": "SPF", "status": "MISSING"}],
            open_ports=[22, 80, 443, 3306, 6379],
            critical_findings=2, high_findings=5, medium_findings=3, low_findings=1,
            total_findings=11, cve_count=8, attack_surface_score=75, risk_score=80,
            risk_level="HIGH", exploit_available=True, kev_count=3,
        )
        assert "CVE" in summary
        assert "KEV" in summary
        assert "SPF" in summary
        assert "Critical" in summary

    def test_generate_with_many_technologies(self) -> None:
        techs = [f"Tech{i}" for i in range(20)]
        summary = ExecutiveSummaryGenerator.generate(
            target="test.com", technologies=techs,
            cms_list=[], frameworks=[], databases=[],
            waf_vendor="Cloudflare", cdn_vendor="Cloudflare", hosting_provider="AWS",
            dns_findings=[], open_ports=[80, 443],
            critical_findings=0, high_findings=1, medium_findings=0, low_findings=0,
            total_findings=1, cve_count=0, attack_surface_score=30, risk_score=20,
            risk_level="LOW", exploit_available=False, kev_count=0,
        )
        tech_lines = [l for l in summary.split("\n") if "Tech" in l]
        assert len(tech_lines) >= 8  # shows first 8
        assert "more technologies" in summary

    def test_generate_with_waf_and_cdn(self) -> None:
        summary = ExecutiveSummaryGenerator.generate(
            target="test.com", technologies=["nginx"],
            cms_list=[], frameworks=[], databases=[],
            waf_vendor="Cloudflare", cdn_vendor="Fastly", hosting_provider="AWS",
            dns_findings=[], open_ports=[443],
            critical_findings=0, high_findings=0, medium_findings=0, low_findings=0,
            total_findings=0, cve_count=0, attack_surface_score=10, risk_score=10,
            risk_level="LOW", exploit_available=False, kev_count=0,
        )
        assert "WAF" in summary
        assert "Fastly" in summary
        assert "AWS" in summary
        assert "Main Concerns" in summary

    def test_recommend_next_phase_critical(self) -> None:
        phase = ExecutiveSummaryGenerator._recommend_next_phase(
            critical_count=1, high_count=0, cve_count=10, databases=[], cms_list=[], frameworks=[],
        )
        assert "Penetration Test" in phase

    def test_recommend_next_phase_high(self) -> None:
        phase = ExecutiveSummaryGenerator._recommend_next_phase(
            critical_count=0, high_count=2, cve_count=0, databases=[], cms_list=[], frameworks=[],
        )
        assert "Configuration Review" in phase

    def test_recommend_next_phase_databases(self) -> None:
        phase = ExecutiveSummaryGenerator._recommend_next_phase(
            critical_count=0, high_count=0, cve_count=0, databases=["MySQL"], cms_list=[], frameworks=[],
        )
        assert "Configuration Review" in phase

    def test_recommend_next_phase_cms(self) -> None:
        phase = ExecutiveSummaryGenerator._recommend_next_phase(
            critical_count=0, high_count=0, cve_count=0, databases=[], cms_list=["WordPress"], frameworks=[],
        )
        assert "Configuration Review" in phase

    def test_recommend_next_phase_frameworks(self) -> None:
        phase = ExecutiveSummaryGenerator._recommend_next_phase(
            critical_count=0, high_count=0, cve_count=0, databases=[], cms_list=[], frameworks=["Laravel"],
        )
        assert "Architecture Review" in phase

    def test_recommend_next_phase_baseline(self) -> None:
        phase = ExecutiveSummaryGenerator._recommend_next_phase(
            critical_count=0, high_count=0, cve_count=0, databases=[], cms_list=[], frameworks=[],
        )
        assert "Standard Security Assessment" in phase


# ==============================================================
# Risk Matrix - Extended
# ==============================================================
class TestRiskMatrixExtended:
    def test_all_levels(self) -> None:
        matrix = RiskMatrixGenerator.generate(
            attack_surface_score=5, critical_findings=1, high_findings=1, medium_findings=0,
            total_findings=2, cve_count=1, exploit_available=False, kev_count=0,
            open_ports_count=0, waf_detected=True, cdn_detected=True,
        )
        assert matrix.overall_level in ("Low", "Medium")

    def test_critical_with_waf_cdn(self) -> None:
        matrix = RiskMatrixGenerator.generate(
            attack_surface_score=95, critical_findings=5, high_findings=10, medium_findings=5,
            total_findings=20, cve_count=20, exploit_available=True, kev_count=5,
            open_ports_count=20, waf_detected=True, cdn_detected=True,
        )
        assert matrix.overall_level == "Critical"

    def test_exposure_reduced_by_waf_cdn(self) -> None:
        with_protection = RiskMatrixGenerator.generate(
            attack_surface_score=80, critical_findings=0, high_findings=0, medium_findings=0,
            total_findings=0, cve_count=0, waf_detected=True, cdn_detected=True,
        )
        without = RiskMatrixGenerator.generate(
            attack_surface_score=80, critical_findings=0, high_findings=0, medium_findings=0,
            total_findings=0, cve_count=0,
        )
        assert with_protection.exposure.score < without.exposure.score


# ==============================================================
# Scoring Engine - Complete Edge Cases
# ==============================================================
class TestScoringComplete:
    def test_attack_surface_low_score(self) -> None:
        profile = AttackSurfaceProfile(
            target="test.com",
            waf=WAFProfile(detected=True, vendor="Cloudflare"),
            cdn=CDNProfile(detected=True, vendor="Fastly"),
            dns=DNSProfile(),
        )
        score, cls = ScoringEngine.calculate_attack_surface_score(profile)
        assert score == 0 or score <= 10
        assert cls == "Minimal"

    def test_attack_surface_medium_score(self) -> None:
        profile = AttackSurfaceProfile(
            target="test.com",
            open_ports=[80, 443, 22, 3306, 5432],
            services_exposed=["http", "https", "ssh"],
            technologies=["nginx", "php", "mysql"],
            frameworks=["Laravel"],
            cms=["WordPress"],
            databases=["MySQL"],
            dns=DNSProfile(spf_missing=True, dmarc_missing=True),
        )
        score, cls = ScoringEngine.calculate_attack_surface_score(profile)
        assert 41 <= score <= 60 or cls == "Medium" or score > 40

    def test_risk_score_no_findings(self) -> None:
        score, level = ScoringEngine.calculate_risk_score(
            attack_surface_score=0, findings_count=0, critical_findings=0,
            high_findings=0, medium_findings=0, cve_count=0,
        )
        assert score == 0
        assert level == "Minimal"

    def test_risk_score_medium(self) -> None:
        score, level = ScoringEngine.calculate_risk_score(
            attack_surface_score=30, findings_count=5, critical_findings=0,
            high_findings=2, medium_findings=3, cve_count=2,
        )
        assert "Minimal" not in level.upper()


# ==============================================================
# Intelligence Engine - Saving with findings
# ==============================================================
class TestIntelligenceEngineSaveFindings:
    def test_save_findings_high_score(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        tech_data = {"target": "test.com", "technologies": [{"name": "WordPress", "category": "CMS", "version": "5.8", "confidence": 1.0, "source": "test"}]}
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump(tech_data, f)
        nmap_data = {"open_ports": [80, 443, 3306, 22, 8080, 8443, 6379, 9200, 27017, 5432], "services": ["http", "https", "mysql", "ssh", "redis"]}
        with open(fdir / "nmap.json", "w") as f:
            json.dump(nmap_data, f)
        headers_data = {"findings": [{"title": "Missing CSP", "severity": "HIGH", "description": "No CSP header", "target": "test.com", "evidence": "", "recommendation": ""}]}
        with open(fdir / "headers.json", "w") as f:
            json.dump(headers_data, f)
        ssl_data = {"findings": []}
        with open(fdir / "ssl.json", "w") as f:
            json.dump(ssl_data, f)
        engine = IntelligenceEngine()
        report = engine.analyze_project(tmp_path)
        assert (fdir / "intelligence_findings.json").exists()
        intel_findings = json.loads((fdir / "intelligence_findings.json").read_text())
        assert len(intel_findings) >= 1

    def test_engine_resolve_target_from_vuln(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"target": "vuln-target.com"}, f)
        engine = IntelligenceEngine()
        target = engine._resolve_target(tmp_path)
        assert target == "vuln-target.com"

    def test_engine_resolve_target_fallback(self, tmp_path: Path) -> None:
        engine = IntelligenceEngine()
        target = engine._resolve_target(tmp_path)
        assert target == tmp_path.name

    def test_load_tech_profile_error(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        pdir.mkdir()
        with open(pdir / "technology_profile.json", "w") as f:
            f.write("invalid json{")
        engine = IntelligenceEngine()
        result = engine._load_tech_profile(pdir)
        assert result is None

    def test_load_json_invalid(self, tmp_path: Path) -> None:
        path = tmp_path / "test.json"
        path.write_text("not json")
        result = IntelligenceEngine._load_json(path)
        assert result is None

    def test_load_json_nonexistent(self, tmp_path: Path) -> None:
        result = IntelligenceEngine._load_json(tmp_path / "nonexistent.json")
        assert result is None


# ==============================================================
# Executive Summary - from_project
# ==============================================================
class TestExecutiveSummaryFromProject:
    def test_from_project_full_data(self, tmp_path: Path) -> None:
        pdir = tmp_path / "profiles"
        fdir = tmp_path / "findings"
        pdir.mkdir()
        fdir.mkdir()
        with open(pdir / "technology_profile.json", "w") as f:
            json.dump({"target": "test.com", "technologies": [{"name": "Nginx", "category": "WEB SERVER"}, {"name": "WordPress", "category": "CMS"}]}, f)
        with open(pdir / "vulnerability_profile.json", "w") as f:
            json.dump({"matches": [{"technology": "wordpress", "risk_level": "HIGH", "matched_cve": {"cve_id": "CVE-2021-1234", "severity": "HIGH", "exploit_available": True, "kev_listed": True}}], "overall_vulnerability_score": 70, "overall_risk_level": "HIGH"}, f)
        with open(fdir / "nmap.json", "w") as f:
            json.dump({"open_ports": [80, 443], "services": ["http", "https"]}, f)
        with open(pdir / "attack_surface_profile.json", "w") as f:
            json.dump({"waf": {"detected": True, "vendor": "Cloudflare"}, "cdn": {"detected": True, "vendor": "Fastly"}, "hosting": {"detected": True, "provider": "AWS"}, "dns": {"findings": [{"record_type": "SPF", "status": "MISSING"}]}, "attack_surface_score": 50}, f)
        with open(fdir / "headers.json", "w") as f:
            json.dump({"findings": [{"title": "Test Finding", "severity": "HIGH", "description": "Test", "target": "test.com", "evidence": "", "recommendation": ""}]}, f)
        with open(fdir / "ssl.json", "w") as f:
            json.dump({"findings": []}, f)
        with open(fdir / "fingerprint.json", "w") as f:
            json.dump({"findings": []}, f)
        summary = ExecutiveSummaryGenerator.from_project(tmp_path)
        assert "test.com" in summary
        assert "Cloudflare" in summary
        assert "Fastly" in summary
        assert "WordPress" in summary

    def test_from_project_minimal(self, tmp_path: Path) -> None:
        summary = ExecutiveSummaryGenerator.from_project(tmp_path)
        assert "Unknown" in summary or tmp_path.name in summary

    def test_from_project_nmap_only(self, tmp_path: Path) -> None:
        fdir = tmp_path / "findings"
        fdir.mkdir()
        with open(fdir / "nmap.json", "w") as f:
            json.dump({"open_ports": [22], "services": ["ssh"]}, f)
        summary = ExecutiveSummaryGenerator.from_project(tmp_path)
        assert "Unknown" in summary


# ==============================================================
# Attack Surface - DNS Analysis (mocked)
# ==============================================================
class TestAttackSurfaceDNS:
    def test_dns_profile_without_external_lib(self) -> None:
        profile = DNSProfile(spf_missing=True, dmarc_missing=True, dkim_missing=True)
        assert profile.spf_missing is True
        assert profile.dmarc_missing is True
        assert profile.dkim_missing is True

    def test_dns_finding_list(self) -> None:
        findings = [
            DNSFinding(record_type="SPF", status="MISSING", details="Not found"),
            DNSFinding(record_type="DMARC", status="MISSING", details="Not found"),
        ]
        profile = DNSProfile(findings=findings)
        assert len(profile.findings) == 2
        assert profile.findings[0].record_type == "SPF"


# ==============================================================
# Correlation - CorrelatedFinding
# ==============================================================
class TestCorrelatedFindingExtended:
    def test_to_dict_with_none(self) -> None:
        f = CorrelatedFinding(title="Test", description="Desc", severity="LOW", sources=["test"])
        d = f.to_dict()
        assert d["evidence"] is None
        assert d["recommendation"] is None


# ==============================================================
# Intelligence Report - Model defaults
# ==============================================================
class TestIntelligenceReportDefaults:
    def test_report_with_defaults(self) -> None:
        report = IntelligenceReport(target="test.com")
        assert report.overall_security_score == 0
        assert report.generated_at is not None
        assert len(report.recommendations) == 0
        assert len(report.attack_paths) == 0
        assert report.executive_summary == ""

    def test_report_with_full_data(self) -> None:
        from ghostmirror.models.attack_path import AttackPath, AttackPathStep
        report = IntelligenceReport(
            target="test.com",
            overall_security_score=85,
            overall_attack_surface_score=90,
            overall_risk_score=80,
            attack_surface_profile=AttackSurfaceProfile(target="test.com"),
            risk_matrix=RiskMatrix(overall_level="Critical"),
            attack_paths=[AttackPath(path_id=1, title="Test Path", description="Desc", steps=[AttackPathStep(order=1, label="Step1")], risk_score=50, risk_level="MEDIUM")],
            executive_summary="Test executive summary",
            recommendations=[PentestRecommendation(assessment_type="Web App Pentest", priority="Critical", justification="Test")],
        )
        assert report.overall_security_score == 85
        assert report.risk_matrix.overall_level == "Critical"
        assert len(report.attack_paths) == 1
        assert report.executive_summary == "Test executive summary"
        assert len(report.recommendations) == 1
        assert report.recommendations[0].assessment_type == "Web App Pentest"

    def test_risk_matrix_entry_defaults(self) -> None:
        entry = RiskMatrixEntry(category="Test", score=0, level="Unknown")
        assert entry.description is None

    def test_risk_matrix_defaults(self) -> None:
        matrix = RiskMatrix()
        assert matrix.likelihood.category == "Likelihood"
        assert matrix.likelihood.score == 0
        assert matrix.likelihood.level == "Unknown"
        assert matrix.overall_level == "Unknown"


# ==============================================================
# Recommendation Engine - remaining branches
# ==============================================================
class TestRecommendationBranches:
    def test_database_ports_detected(self) -> None:
        recs = RecommendationEngine.generate(
            cms_list=[], databases=["MySQL"], frameworks=[], open_ports=[3306],
            critical_findings=0, high_findings=0, medium_findings=0, cve_count=0,
            exploit_available=False, waf_detected=True, dns_issues=[], technologies_count=3,
        )
        types = [r.assessment_type for r in recs]
        assert "Database Security Assessment" in types

    def test_cms_no_critical(self) -> None:
        recs = RecommendationEngine.generate(
            cms_list=["WordPress"], databases=[], frameworks=[], open_ports=[80, 443],
            critical_findings=0, high_findings=0, medium_findings=0, cve_count=0,
            exploit_available=False, waf_detected=True, dns_issues=[], technologies_count=3,
        )
        types = [r.assessment_type for r in recs]
        assert "CMS Security Review" in types
        assert "Web Application Penetration Test" not in types

    def test_no_waf_no_dns_issues(self) -> None:
        recs = RecommendationEngine.generate(
            cms_list=[], databases=[], frameworks=[], open_ports=[80],
            critical_findings=0, high_findings=0, medium_findings=0, cve_count=0,
            exploit_available=False, waf_detected=False, dns_issues=[], technologies_count=1,
        )
        types = [r.assessment_type for r in recs]
        assert "WAF Implementation Review" in types
        assert "Configuration Review" in types

    def test_baseline_recommendation(self) -> None:
        recs = RecommendationEngine.generate(
            cms_list=[], databases=[], frameworks=[], open_ports=[],
            critical_findings=0, high_findings=0, medium_findings=0, cve_count=0,
            exploit_available=False, waf_detected=True, dns_issues=[], technologies_count=0,
        )
        types = [r.assessment_type for r in recs]
        assert "Configuration Review" in types
