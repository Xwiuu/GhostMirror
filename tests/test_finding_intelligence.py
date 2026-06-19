import json
import pytest
from pathlib import Path

from ghostmirror.modules.finding_intelligence.engine import FindingIntelligenceEngine
from ghostmirror.modules.finding_intelligence.severity_engine import (
    severity_to_score,
    score_to_severity,
    likelihood_label_from_score,
    exploitability_label_from_score,
)
from ghostmirror.modules.finding_intelligence.recommendation_engine import generate_recommendation
from ghostmirror.modules.finding_intelligence.reference_engine import get_references
from ghostmirror.modules.finding_intelligence.executive_mapper import (
    generate_executive_summary,
    build_priority_matrix,
)
from ghostmirror.models.enriched_finding import EnrichedFinding
from ghostmirror.models.finding_priority import FindingPriority
from ghostmirror.models.finding_intelligence_report import FindingIntelligenceReport


class TestSeverityEngine:
    def test_severity_to_score(self) -> None:
        assert severity_to_score("INFO") == 10
        assert severity_to_score("LOW") == 25
        assert severity_to_score("MEDIUM") == 50
        assert severity_to_score("HIGH") == 75
        assert severity_to_score("CRITICAL") == 100

    def test_severity_case_insensitive(self) -> None:
        assert severity_to_score("critical") == 100
        assert severity_to_score("Medium") == 50

    def test_score_to_severity(self) -> None:
        assert score_to_severity(100) == "CRITICAL"
        assert score_to_severity(70) == "HIGH"
        assert score_to_severity(45) == "MEDIUM"
        assert score_to_severity(25) == "LOW"
        assert score_to_severity(5) == "INFO"
        assert score_to_severity(-5) == "INFO"  # covers negative score fallback

    def test_likelihood_labels(self) -> None:
        assert likelihood_label_from_score(90) == "Critical"
        assert likelihood_label_from_score(70) == "High"
        assert likelihood_label_from_score(50) == "Medium"
        assert likelihood_label_from_score(30) == "Low"
        assert likelihood_label_from_score(5) == "Very Low"

    def test_exploitability_labels_all_levels(self) -> None:
        assert exploitability_label_from_score(90) == "Critical"
        assert exploitability_label_from_score(70) == "High"
        assert exploitability_label_from_score(50) == "Medium"
        assert exploitability_label_from_score(30) == "Low"
        assert exploitability_label_from_score(10) == "Very Low"

    def test_invalid_severity(self) -> None:
        assert severity_to_score("UNKNOWN") == 0


class TestRecommendationEngine:
    def test_recommendation_missing_header(self) -> None:
        rec = generate_recommendation("Missing Content Security Policy")
        assert "Content-Security-Policy" in rec

    def test_recommendation_open_db(self) -> None:
        rec = generate_recommendation("Open Database")
        assert "firewall" in rec.lower() or "acesso" in rec.lower()

    def test_recommendation_generic(self) -> None:
        rec = generate_recommendation("Unknown Issue")
        assert "Revisar" in rec or "melhores práticas" in rec

    def test_recommendation_by_category(self) -> None:
        rec = generate_recommendation("Something", category="Missing Security Header")
        assert "headers" in rec.lower()


class TestReferenceEngine:
    def test_references_headers(self) -> None:
        refs = get_references(category="Security Headers")
        assert len(refs) >= 3
        assert any("owasp" in r for r in refs)
        assert any("cwe" in r for r in refs)

    def test_references_ssl(self) -> None:
        refs = get_references(title="SSL Certificate Expired")
        assert len(refs) >= 3
        assert any("owasp" in r for r in refs)

    def test_references_default(self) -> None:
        refs = get_references()
        assert len(refs) >= 3
        assert any("owasp" in r for r in refs)

    def test_references_cve_title(self) -> None:
        refs = get_references(title="CVE-2024-0001 detected")
        assert len(refs) >= 3
        assert any("cve" in r for r in refs)

    def test_references_auth_category(self) -> None:
        refs = get_references(category="Authentication Bypass")
        assert len(refs) >= 3
        assert any("owasp" in r for r in refs)

    def test_references_category_ssl_tls(self) -> None:
        refs = get_references(category="SSL/TLS")
        assert len(refs) >= 3
        assert any("owasp" in r for r in refs)

    def test_references_category_partial_match(self) -> None:
        refs = get_references(category="Open Port Scan")
        assert len(refs) >= 3
        assert any("cwe" in r for r in refs)


class TestExecutiveMapper:
    def test_generate_executive_summary(self) -> None:
        report = FindingIntelligenceReport(
            project="test",
            target="example.com",
            total_findings=10,
            total_enriched=10,
            priority_counts={"P1": 2, "P2": 3, "P3": 2, "P4": 2, "P5": 1},
            priority_matrix={"P1": 2, "P2": 3, "P3": 2, "P4": 2, "P5": 1},
            kev_count=5,
            exploit_count=3,
        )
        summary = generate_executive_summary(report)
        assert "10 findings" in summary
        assert "P1" in summary
        assert "KEV" in summary

    def test_build_priority_matrix(self) -> None:
        findings = [
            EnrichedFinding(title="A", severity="CRITICAL", priority=FindingPriority.P1),
            EnrichedFinding(title="B", severity="HIGH", priority=FindingPriority.P1),
            EnrichedFinding(title="C", severity="MEDIUM", priority=FindingPriority.P3),
        ]
        matrix = build_priority_matrix(findings)
        assert matrix["P1"] == 2
        assert matrix["P3"] == 1


class TestFindingIntelligenceEngine:
    def test_load_all_findings_empty_dir(self, tmp_path: Path) -> None:
        engine = FindingIntelligenceEngine()
        findings = engine._load_all_findings(tmp_path)
        assert findings == []

    def test_load_findings_with_data(self, tmp_path: Path) -> None:
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        data = {"findings": [{"title": "Test", "severity": "HIGH"}]}
        fpath = findings_dir / "headers.json"
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f)

        engine = FindingIntelligenceEngine()
        findings = engine._load_all_findings(tmp_path)
        assert len(findings) == 1
        assert findings[0]["title"] == "Test"
        assert findings[0]["source"] == "headers"

    def test_load_findings_json_list_format(self, tmp_path: Path) -> None:
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        data = [{"title": "ListItem1", "severity": "LOW"}, {"title": "ListItem2", "severity": "MEDIUM"}]
        fpath = findings_dir / "nuclei.json"
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f)

        engine = FindingIntelligenceEngine()
        findings = engine._load_all_findings(tmp_path)
        assert len(findings) == 2
        assert findings[0]["source"] == "nuclei"

    def test_load_findings_corrupt_json(self, tmp_path: Path) -> None:
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        fpath = findings_dir / "bad.json"
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("not valid json")

        engine = FindingIntelligenceEngine()
        findings = engine._load_all_findings(tmp_path)
        assert findings == []

    def test_resolve_target(self, tmp_path: Path) -> None:
        meta_path = tmp_path / "metadata.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"name": "test", "domain": "example.com"}, f)

        engine = FindingIntelligenceEngine()
        target = engine._resolve_target(tmp_path)
        assert target == "example.com"

    def test_resolve_target_no_meta(self, tmp_path: Path) -> None:
        engine = FindingIntelligenceEngine()
        target = engine._resolve_target(tmp_path)
        assert target == ""

    def test_resolve_target_corrupt_meta(self, tmp_path: Path) -> None:
        meta_path = tmp_path / "metadata.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            f.write("{corrupt")

        engine = FindingIntelligenceEngine()
        target = engine._resolve_target(tmp_path)
        assert target == ""

    def test_sort_key(self) -> None:
        engine = FindingIntelligenceEngine()
        ef_p1 = EnrichedFinding(title="P1 Finding", severity="CRITICAL", priority=FindingPriority.P1)
        ef_p5 = EnrichedFinding(title="P5 Finding", severity="INFO", priority=FindingPriority.P5)
        key_p1 = engine._sort_key(ef_p1)
        key_p5 = engine._sort_key(ef_p5)
        assert key_p1 > key_p5

    def test_is_quick_win(self) -> None:
        engine = FindingIntelligenceEngine()
        ef = EnrichedFinding(title="Missing Security Header", severity="MEDIUM", priority=FindingPriority.P4)
        assert engine._is_quick_win(ef)

        ef2 = EnrichedFinding(title="Complex Issue", severity="HIGH", priority=FindingPriority.P2)
        assert not engine._is_quick_win(ef2)

    def test_enrich_finding_raises_exception_skipped(self, tmp_path: Path) -> None:
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "profiles").mkdir()
        data = {"findings": [{"title": "", "severity": "LOW"}]}
        fpath = findings_dir / "headers.json"
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f)

        engine = FindingIntelligenceEngine()
        report = engine.analyze_project(tmp_path)
        assert report.total_findings == 1
        assert report.total_enriched == 0

    def test_full_engine_analyze(self, tmp_path: Path) -> None:
        # Create project structure
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir()

        meta_path = tmp_path / "metadata.json"
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"name": "test", "domain": "example.com"}, f)

        data = {
            "findings": [
                {"title": "Missing CSP", "severity": "MEDIUM", "category": "Security Headers", "evidence": "No CSP header"},
                {"title": "Open Port 22", "severity": "HIGH", "category": "Open Port", "cvss": 7.5, "kev": False},
                {"title": "CVE-2024-0001", "severity": "CRITICAL", "cvss": 9.8, "epss": 0.9, "kev": True, "source": "nuclei"},
            ]
        }
        fpath = findings_dir / "headers.json"
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(data, f)

        engine = FindingIntelligenceEngine()
        report = engine.analyze_project(tmp_path)

        assert report.total_findings == 3
        assert report.total_enriched == 3
        assert report.priority_counts["P1"] >= 1
        assert report.priority_counts["P4"] >= 1
        assert len(report.top_findings) == 3
        assert len(report.quick_wins) >= 1
        assert report.kev_count >= 1
        assert report.executive_summary is not None

        # Verify files were saved
        assert (profiles_dir / "finding_intelligence_report.json").exists()
        assert (profiles_dir / "enriched_findings.json").exists()
        assert (profiles_dir / "top_findings.json").exists()
        assert (profiles_dir / "quick_wins.json").exists()

        # Verify saved content
        with open(profiles_dir / "finding_intelligence_report.json", "r", encoding="utf-8") as f:
            saved = json.load(f)
        assert saved["total_findings"] == 3
