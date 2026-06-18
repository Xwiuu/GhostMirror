"""Unit tests for the Reporting Engine."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.core.project_manager import ProjectManager
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity, ScanResultModel
from ghostmirror.modules.reporting.collector import ReportCollector
from ghostmirror.modules.reporting.generator import ReportGenerator
from ghostmirror.modules.reporting.html_renderer import HTMLReportRenderer
from ghostmirror.modules.reporting.markdown_renderer import MarkdownReportRenderer
from ghostmirror.modules.reporting.pdf_renderer import PDFReportRenderer
from ghostmirror.modules.reporting.scoring import ReportScorer


def test_report_scorer_no_findings():
    """Verify score is 0 and level is LOW when no findings exist."""
    score, level = ReportScorer.calculate_score([])
    assert score == 0
    assert level == "LOW"


def test_report_scorer_severities_weighting():
    """Test severity weights and caps at 100."""
    findings = [
        FindingModel(
            title="Finding 1",
            description="Desc 1",
            severity=FindingSeverity.CRITICAL,
            target="example.com",
            recommendation="Rec 1",
        ),
        FindingModel(
            title="Finding 2",
            description="Desc 2",
            severity=FindingSeverity.HIGH,
            target="example.com",
            recommendation="Rec 2",
        ),
        FindingModel(
            title="Finding 3",
            description="Desc 3",
            severity=FindingSeverity.MEDIUM,
            target="example.com",
            recommendation="Rec 3",
        ),
        FindingModel(
            title="Finding 4",
            description="Desc 4",
            severity=FindingSeverity.LOW,
            target="example.com",
            recommendation="Rec 4",
        ),
        FindingModel(
            title="Finding 5",
            description="Desc 5",
            severity=FindingSeverity.INFO,
            target="example.com",
            recommendation="Rec 5",
        ),
    ]

    # Raw score: 30 + 20 + 10 + 5 + 1 = 66
    score, level = ReportScorer.calculate_score(findings)
    assert score == 66
    assert level == "HIGH"

    # Add enough critical findings to exceed 100
    many_findings = findings + [findings[0]] * 2  # + 60 -> 126
    score, level = ReportScorer.calculate_score(many_findings)
    assert score == 100
    assert level == "CRITICAL"


def test_report_scorer_with_profiles():
    """Test score blending with risk and vulnerability profiles."""
    findings = [
        FindingModel(
            title="Finding 1",
            description="Desc 1",
            severity=FindingSeverity.HIGH,
            target="example.com",
            recommendation="Rec 1",
        )
    ]
    # Findings score = 20
    # Risk Profile score = 80
    # Vuln Profile score = 60
    # Expected blended score: 0.5*20 + 0.15*80 + 0.15*60 + 0.2*0 = 10 + 12 + 9 + 0 = 31
    score, level = ReportScorer.calculate_score(
        all_findings=findings,
        risk_profile={"risk_score": 80},
        vulnerability_profile={"overall_vulnerability_score": 60},
    )
    assert score == 31
    assert level == "MEDIUM"


def test_report_collector_missing_files(tmp_path: Path):
    """Collector should handle missing files gracefully."""
    collector = ReportCollector(tmp_path)
    data = collector.collect()
    
    assert data["findings"]["headers"] is None
    assert data["findings"]["cve_findings"] == []
    assert data["all_findings"] == []


def test_report_collector_aggregates_findings(project_manager: ProjectManager):
    """Collector should load and deduplicate findings from different modules."""
    handle = project_manager.create_project(
        client="Acme", name="Pentest", domain="acme.com"
    )

    findings_dir = handle.path / "findings"
    
    # Save dummy headers finding
    header_res = ScanResultModel(
        scanner_name="headers",
        target="acme.com",
        started_at="2026-06-18T10:00:00Z",
        finished_at="2026-06-18T10:05:00Z",
        status="completed",
        findings=[
            FindingModel(
                title="Missing Secure Headers",
                description="Secure headers missing",
                severity=FindingSeverity.LOW,
                target="acme.com",
                recommendation="Add headers",
            )
        ]
    )
    
    with open(findings_dir / "headers.json", "w", encoding="utf-8") as f:
        json.dump(header_res.model_dump(mode="json"), f)

    # Save CVE finding with identical title/desc to test deduplication
    cve_findings = [
        FindingModel(
            title="Missing Secure Headers",
            description="Secure headers missing",
            severity=FindingSeverity.LOW,
            target="acme.com",
            recommendation="Add headers",
        ),
        FindingModel(
            title="Different Finding",
            description="New description",
            severity=FindingSeverity.HIGH,
            target="acme.com",
            recommendation="Fix it",
        )
    ]
    with open(findings_dir / "cve_findings.json", "w", encoding="utf-8") as f:
        json.dump([item.model_dump(mode="json") for item in cve_findings], f)

    collector = ReportCollector(handle.path)
    data = collector.collect()

    # Total aggregated unique findings should be 2
    assert len(data["all_findings"]) == 2
    titles = [f.title for f in data["all_findings"]]
    assert "Missing Secure Headers" in titles
    assert "Different Finding" in titles


def test_html_and_markdown_renderers():
    """Verify HTML and MD renderers produce valid string content containing findings."""
    data = {
        "all_findings": [
            FindingModel(
                title="Test Finding 1",
                description="Testing descriptions",
                severity=FindingSeverity.HIGH,
                target="target.com",
                recommendation="Clean it",
                evidence="HTTP/1.1 200 OK"
            )
        ],
        "profiles": {
            "technology_profile": {
                "target": "target.com",
                "technologies": [{"name": "Apache", "version": "2.4.41", "categories": ["web-server"]}]
            },
            "vulnerability_profile": {
                "target": "target.com",
                "matches": [
                    {
                        "matched_cve": {"cve_id": "CVE-2020-0001", "exploit_available": True},
                        "technology": "Apache",
                        "risk_level": "HIGH"
                    }
                ]
            }
        }
    }

    html = HTMLReportRenderer.render(
        project_name="Acme Project",
        target="target.com",
        profile="standard",
        score=75,
        risk_level="CRITICAL",
        collected_data=data,
    )
    assert "<html" in html
    assert "Test Finding 1" in html
    assert "Apache" in html
    assert "CVE-2020-0001" in html

    md = MarkdownReportRenderer.render(
        project_name="Acme Project",
        target="target.com",
        profile="standard",
        score=75,
        risk_level="CRITICAL",
        collected_data=data,
    )
    assert "# GHOSTMIRROR SECURITY ASSESSMENT" in md
    assert "Test Finding 1" in md
    assert "CVE-2020-0001" in md


def test_pdf_renderer_graceful_fallback(tmp_path: Path):
    """PDF renderer must fail gracefully if weasyprint cannot be imported or runs into errors."""
    html_content = "<html><body>Hello</body></html>"
    pdf_path = tmp_path / "report.pdf"

    # Test error behavior when weasyprint fails on import (OSError or ImportError)
    with patch("builtins.__import__", side_effect=OSError("Failed to link pango/gobject libraries")):
        success = PDFReportRenderer.render(html_content, pdf_path)
        assert success is False
        assert not pdf_path.exists()


def test_report_generator_integration(project_manager: ProjectManager):
    """Test generating html, md, and pdf reports via ReportGenerator."""
    handle = project_manager.create_project(
        client="Acme", name="Pentest", domain="acme.com"
    )

    generator = ReportGenerator(handle.path)
    
    with patch("ghostmirror.modules.reporting.pdf_renderer.PDFReportRenderer.render") as mock_pdf_render:
        def side_effect(html, path):
            Path(path).write_text("mock pdf data")
            return True
        mock_pdf_render.side_effect = side_effect
        
        res = generator.generate("all")
        
        assert res["score"] == 0
        assert res["risk_level"] == "LOW"
        assert len(res["generated_files"]) == 3
        
        assert (handle.path / "reports" / "report.html").exists()
        assert (handle.path / "reports" / "report.md").exists()
        assert (handle.path / "reports" / "report.pdf").exists()
