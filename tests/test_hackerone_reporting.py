"""Tests for the HackerOne style reporting engine."""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghostmirror.models.bounty_severity import BountySeverity, BountyPriority
from ghostmirror.models.bounty_submission import BountySubmission
from ghostmirror.models.bounty_report import BountyReport
from ghostmirror.models.reproduction_step import ReproductionStep
from ghostmirror.models.evidence_block import EvidenceBlock
from ghostmirror.modules.hackerone_reporting.severity_mapper import SeverityMapper
from ghostmirror.modules.hackerone_reporting.reproduction_steps import SafeReproductionStepGenerator
from ghostmirror.modules.hackerone_reporting.impact_writer import ImpactWriter
from ghostmirror.modules.hackerone_reporting.evidence_formatter import EvidenceFormatter
from ghostmirror.modules.hackerone_reporting.remediation_writer import RemediationWriter
from ghostmirror.modules.hackerone_reporting.references_mapper import ReferencesMapper
from ghostmirror.modules.hackerone_reporting.submission_builder import SubmissionBuilder
from ghostmirror.modules.hackerone_reporting.engine import HackerOneReportingEngine
from ghostmirror.modules.hackerone_reporting.template_renderer import TemplateRenderer
from ghostmirror.modules.hackerone_reporting.markdown_exporter import MarkdownExporter
from ghostmirror.modules.hackerone_reporting.json_exporter import JSONExporter
from ghostmirror.modules.hackerone_reporting.html_exporter import HTMLExporter
from ghostmirror.modules.hackerone_reporting.report_index import ReportIndex


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def sample_submission():
    return BountySubmission(
        title="Missing Content-Security-Policy Header",
        severity=BountySeverity.MEDIUM,
        priority=BountyPriority.P3,
        affected_asset="https://example.com",
        affected_endpoint="/",
        category="Missing Security Header",
        cwe="CWE-693",
        cvss=5.0,
        epss=0.01,
        confidence="High",
        summary="The X-Content-Security-Policy header is missing from HTTP responses.",
        impact={"business": "May increase risk of XSS attacks.", "technical": "Missing CSP header."},
        steps_to_reproduce=[
            ReproductionStep(step_number=1, description="Send GET request.", expected_observation="200 OK"),
        ],
        evidence=[EvidenceBlock(type="http_headers", label="Headers", content="Content-Type: text/html", redacted=False)],
        remediation="Add Content-Security-Policy header.",
        references=["https://owasp.org/www-project-secure-headers/"],
        generated_from="enriched_finding",
    )


@pytest.fixture
def sample_enriched_finding():
    return {
        "title": "Missing CSP Header",
        "severity": "MEDIUM",
        "category": "Missing Security Header",
        "cvss": 5.0,
        "epss": 0.01,
        "confidence": "HIGH",
        "affected_asset": "https://example.com",
        "evidence": "HTTP/1.1 200 OK\nContent-Type: text/html\n",
        "cwe": "CWE-693",
    }


@pytest.fixture
def sample_hypothesis():
    return {
        "title": "Potential Business Logic Flaw in Checkout",
        "confidence": "LOW",
    }


@pytest.fixture
def empty_project_data():
    return {"findings": {}, "profiles": {}}


@pytest.fixture
def project_data_with_findings():
    return {
        "findings": {},
        "profiles": {
            "enriched_findings": [
                {"title": "Missing HSTS Header", "severity": "HIGH", "category": "Missing Security Header", "confidence": "HIGH", "affected_asset": "https://example.com",
                 "evidence": "HTTP/1.1 200 OK", "cwe": "CWE-693"},
                {"title": "Open Redirect Indicator", "severity": "MEDIUM", "category": "Open Redirect", "confidence": "MEDIUM", "affected_asset": "https://example.com/redirect?url=",
                 "evidence": "", "cwe": "CWE-601"},
            ],
            "zero_day_hypotheses": [
                {"title": "Admin Endpoint Discovery", "confidence": "LOW"},
            ],
        },
    }


# --------------------------------------------------------------------------- #
# Model Tests
# --------------------------------------------------------------------------- #

class TestBountySubmission:
    def test_create_minimal(self):
        sub = BountySubmission(title="Test Finding")
        assert sub.title == "Test Finding"
        assert sub.severity == BountySeverity.INFORMATIONAL
        assert sub.priority == BountyPriority.P5
        assert sub.id is not None
        assert len(sub.id) > 0

    def test_create_full(self, sample_submission):
        sub = sample_submission
        assert sub.title == "Missing Content-Security-Policy Header"
        assert sub.severity == BountySeverity.MEDIUM
        assert sub.priority == BountyPriority.P3
        assert len(sub.steps_to_reproduce) == 1
        assert len(sub.evidence) == 1
        assert len(sub.references) == 1

    def test_auto_id(self):
        sub1 = BountySubmission(title="A")
        sub2 = BountySubmission(title="B")
        assert sub1.id != sub2.id

    def test_serialization(self, sample_submission):
        data = sample_submission.model_dump()
        assert data["title"] == "Missing Content-Security-Policy Header"
        assert data["severity"] == "Medium"
        assert data["priority"] == "P3"


class TestBountyReport:
    def test_create_empty(self):
        report = BountyReport()
        assert report.target == ""
        assert report.submissions == []
        assert report.summary_stats["total"] == 0

    def test_create_with_submissions(self, sample_submission):
        report = BountyReport(
            target="example.com",
            submissions=[sample_submission],
        )
        assert report.target == "example.com"
        assert len(report.submissions) == 1

    def test_summary_stats_defaults(self):
        report = BountyReport()
        assert report.summary_stats["critical"] == 0
        assert report.summary_stats["high"] == 0
        assert report.summary_stats["medium"] == 0
        assert report.summary_stats["low"] == 0
        assert report.summary_stats["informational"] == 0


class TestReproductionStep:
    def test_create(self):
        step = ReproductionStep(step_number=1, description="Test step")
        assert step.step_number == 1
        assert step.description == "Test step"
        assert step.safe is True

    def test_auto_safe(self):
        step = ReproductionStep(step_number=1, description="Test")
        assert step.safe is True


class TestEvidenceBlock:
    def test_create(self):
        block = EvidenceBlock(type="http_headers", label="Test", content="data")
        assert block.type == "http_headers"
        assert block.redacted is False

    def test_sanitized_secret(self):
        block = EvidenceBlock(type="sanitized_secret", label="Key", content="[REDACTED]", redacted=True)
        assert block.redacted is True


class TestBountySeverity:
    def test_values(self):
        assert BountySeverity.INFORMATIONAL.value == "Informational"
        assert BountySeverity.LOW.value == "Low"
        assert BountySeverity.MEDIUM.value == "Medium"
        assert BountySeverity.HIGH.value == "High"
        assert BountySeverity.CRITICAL.value == "Critical"

    def test_priority_values(self):
        assert BountyPriority.P1.value == "P1"
        assert BountyPriority.P2.value == "P2"
        assert BountyPriority.P3.value == "P3"
        assert BountyPriority.P4.value == "P4"
        assert BountyPriority.P5.value == "P5"


# --------------------------------------------------------------------------- #
# Severity Mapper Tests
# --------------------------------------------------------------------------- #

class TestSeverityMapperIntegration:
    def test_all_mappings(self):
        mapper = SeverityMapper()
        assert mapper.map_severity("CRITICAL") == "Critical"
        assert mapper.map_priority_to_severity("P1") == "Critical"
        assert mapper.map_confidence("CONFIRMED") == "Confirmed"
        assert mapper.map_severity_to_priority("CRITICAL") == "P1"
        assert mapper.map_severity_to_priority("INFO") == "P5"


# --------------------------------------------------------------------------- #
# Reproduction Steps Tests
# --------------------------------------------------------------------------- #

class TestReproductionStepsIntegration:
    def test_missing_header(self):
        steps = SafeReproductionStepGenerator.from_finding({"title": "Missing CSP Header", "category": "Missing Security Header"})
        assert len(steps) == 3
        assert all(s.safe for s in steps)
        assert "GET request" in steps[0].description or "request" in steps[0].description.lower()

    def test_open_redirect(self):
        steps = SafeReproductionStepGenerator.from_finding({"title": "Open Redirect Indicator", "category": "Open Redirect"})
        assert len(steps) >= 2
        assert all(s.safe for s in steps)

    def test_hypothesis(self):
        steps = SafeReproductionStepGenerator.from_finding({"title": "Test", "category": "hypothesis"})
        assert len(steps) == 3
        assert "manual" in steps[1].description.lower() or "Manual" in steps[1].description

    def test_unknown_finding(self):
        steps = SafeReproductionStepGenerator.from_finding({"title": "Unknown", "category": "Misc"})
        assert len(steps) == 2
        assert all(s.safe for s in steps)

    def test_no_exploit_steps(self):
        steps = SafeReproductionStepGenerator.from_finding({"title": "Missing CSP Header", "category": "Missing Security Header"})
        descriptions = " ".join(s.description.lower() for s in steps)
        assert "exploit" not in descriptions
        assert "payload" not in descriptions
        assert "bypass" not in descriptions

    def test_dict_finding(self):
        steps = SafeReproductionStepGenerator.from_finding({"title": "Missing CSP Header"})
        assert len(steps) == 3

    def test_object_finding(self):
        class FakeFinding:
            title = "Missing CSP Header"
            category = "Missing Security Header"
        steps = SafeReproductionStepGenerator.from_finding(FakeFinding())
        assert len(steps) == 3


# --------------------------------------------------------------------------- #
# Impact Writer Tests
# --------------------------------------------------------------------------- #

class TestImpactWriter:
    def test_business_impact(self):
        imp = ImpactWriter.write_business_impact(title="Missing CSP Header", category="Missing Security Header")
        assert len(imp) > 10
        assert "weakness" in imp.lower() or "attack" in imp.lower()

    def test_technical_impact(self):
        imp = ImpactWriter.write_technical_impact(title="Missing CSP Header")
        assert len(imp) > 10

    def test_impact_section(self):
        section = ImpactWriter.write_impact_section(title="Open Redirect", category="Open Redirect")
        assert "business" in section
        assert "technical" in section
        assert len(section["business"]) > 10
        assert len(section["technical"]) > 10

    def test_unknown_category(self):
        imp = ImpactWriter.write_business_impact(title="Unknown")
        assert len(imp) > 0


# --------------------------------------------------------------------------- #
# Evidence Formatter Tests
# --------------------------------------------------------------------------- #

class TestEvidenceFormatter:
    def test_redact_sensitive_bearer(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.dGVzdA.test"
        redacted = EvidenceFormatter.redact_sensitive(text)
        assert "Bearer [REDACTED]" in redacted

    def test_redact_sensitive_jwt(self):
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZw"
        redacted = EvidenceFormatter.redact_sensitive(text)
        assert "[JWT REDACTED]" in redacted

    def test_redact_github_token(self):
        text = "gh" + "p_abcdefghijklmnopqrstuvwxyz1234567890"
        redacted = EvidenceFormatter.redact_sensitive(text)
        assert "[GITHUB_TOKEN REDACTED]" in redacted

    def test_redact_aws_key(self):
        text = "AKI" + "A1234567890ABCDEF"
        redacted = EvidenceFormatter.redact_sensitive(text)
        assert "AKIA[REDACTED]" in redacted

    def test_redact_stripe_key(self):
        prefix = "sk_l"
        text = prefix + "ive_abcdefghijklmnopqrstuvwxyz"
        redacted = EvidenceFormatter.redact_sensitive(text)
        assert "[STRIPE_KEY REDACTED]" in redacted

    def test_redact_password(self):
        text = 'password = "super_secret_123"'
        redacted = EvidenceFormatter.redact_sensitive(text)
        assert "[REDACTED]" in redacted

    def test_create_header_evidence(self):
        headers = {"Content-Type": "text/html", "X-Frame-Options": "DENY"}
        block = EvidenceFormatter.create_header_evidence(headers)
        assert block.type == "http_headers"
        assert "Content-Type" in block.content

    def test_create_url_evidence(self):
        block = EvidenceFormatter.create_url_evidence("https://example.com")
        assert block.type == "url"
        assert "example.com" in block.content

    def test_create_sanitized_secret(self):
        block = EvidenceFormatter.create_sanitized_secret_evidence("API Key", hint="Stripe key found")
        assert block.redacted is True
        assert "REDACTED" in block.content

    def test_create_hypothesis_evidence(self):
        signals = ["Anomalous status code 500", "Rare endpoint /admin"]
        block = EvidenceFormatter.create_hypothesis_evidence(signals)
        assert block.type == "hypothesis_signal"
        assert "500" in block.content

    def test_format_from_finding_dict(self):
        finding = {"evidence": "Authorization: Bearer tok123"}
        blocks = EvidenceFormatter.format_from_finding(finding)
        assert len(blocks) == 1
        assert "[REDACTED]" in blocks[0].content

    def test_format_from_finding_empty(self):
        finding = {"evidence": ""}
        blocks = EvidenceFormatter.format_from_finding(finding)
        assert len(blocks) == 0

    def test_format_from_finding_no_evidence(self):
        finding = {"title": "test"}
        blocks = EvidenceFormatter.format_from_finding(finding)
        assert len(blocks) == 0


# --------------------------------------------------------------------------- #
# Remediation Writer Tests
# --------------------------------------------------------------------------- #

class TestRemediationWriter:
    def test_missing_csp(self):
        rem = RemediationWriter.generate(category="", title="Missing CSP Header")
        assert "Content-Security-Policy" in rem

    def test_open_redirect(self):
        rem = RemediationWriter.generate(category="", title="Open Redirect")
        assert "redirect" in rem.lower()

    def test_jwt(self):
        rem = RemediationWriter.generate(category="", title="JWT Weak Algorithm")
        assert len(rem) > 10

    def test_cve(self):
        rem = RemediationWriter.generate(category="CVE", title="CVE-2023-1234")
        assert len(rem) > 10

    def test_unknown(self):
        rem = RemediationWriter.generate(category="", title="Unknown")
        assert len(rem) > 0


# --------------------------------------------------------------------------- #
# References Mapper Tests
# --------------------------------------------------------------------------- #

class TestReferencesMapper:
    def test_missing_header(self):
        refs = ReferencesMapper.get_references(category="missing_header", title="")
        assert len(refs) > 0
        assert any("owasp" in r for r in refs)

    def test_open_redirect(self):
        refs = ReferencesMapper.get_references(category="", title="Open Redirect")
        assert len(refs) > 0

    def test_cwe_param(self):
        refs = ReferencesMapper.get_references(category="", title="", cwe="CWE-79")
        assert any("79" in r for r in refs)

    def test_default(self):
        refs = ReferencesMapper.get_references(category="", title="Unknown Category")
        assert len(refs) > 0


# --------------------------------------------------------------------------- #
# Submission Builder Tests
# --------------------------------------------------------------------------- #

class TestSubmissionBuilder:
    def test_from_enriched_finding(self, sample_enriched_finding):
        builder = SubmissionBuilder()
        sub = builder.from_enriched_finding(sample_enriched_finding)
        assert sub.title == "Missing CSP Header"
        assert sub.generated_from == "enriched_finding"
        assert len(sub.steps_to_reproduce) > 0
        assert len(sub.references) > 0

    def test_from_zero_day_hypothesis(self, sample_hypothesis):
        builder = SubmissionBuilder()
        sub = builder.from_zero_day_hypothesis(sample_hypothesis)
        assert "[HYPOTHESIS]" in sub.title
        assert sub.generated_from == "zero_day_hypothesis"

    def test_from_web_indicator(self):
        builder = SubmissionBuilder()
        indicator = {"name": "Open Redirect Detected", "severity": "MEDIUM", "category": "Open Redirect", "endpoint": "/redirect?url=", "target": "example.com"}
        sub = builder.from_web_indicator(indicator)
        assert sub.title == "Open Redirect Detected"
        assert sub.generated_from == "web_indicator"

    def test_build_all_empty(self, empty_project_data):
        builder = SubmissionBuilder()
        submissions = builder.build_all(empty_project_data)
        assert submissions == []

    def test_build_all_with_findings(self, project_data_with_findings):
        builder = SubmissionBuilder()
        submissions = builder.build_all(project_data_with_findings)
        assert len(submissions) >= 3  # 2 findings + 1 hypothesis

    def test_build_with_hypotheses_only(self):
        builder = SubmissionBuilder()
        data = {"findings": {}, "profiles": {"enriched_findings": [], "zero_day_hypotheses": [{"title": "Test Hypothesis", "confidence": "LOW"}]}}
        subs = builder.build_all(data)
        assert len(subs) >= 1
        assert any(s.generated_from == "zero_day_hypothesis" for s in subs)


# --------------------------------------------------------------------------- #
# Template Renderer Tests
# --------------------------------------------------------------------------- #

class TestTemplateRenderer:
    def test_render_hackerone(self, sample_submission):
        md = TemplateRenderer.render_hackerone(sample_submission)
        assert "# Missing Content-Security-Policy Header" in md
        assert "**Severity:** Medium" in md
        assert "Steps to Reproduce" in md
        assert "Remediation" in md
        assert "References" in md

    def test_render_bugcrowd(self, sample_submission):
        md = TemplateRenderer.render_bugcrowd(sample_submission)
        assert "# Vulnerability Report: Missing" in md
        assert "VRT Classification" in md

    def test_render_internal_pentest(self, sample_submission):
        md = TemplateRenderer.render_internal_pentest(sample_submission)
        assert "Medium - Missing" in md
        assert "**CWE:**" in md


# --------------------------------------------------------------------------- #
# Markdown Exporter Tests
# --------------------------------------------------------------------------- #

class TestMarkdownExporter:
    def test_export_submission_hackerone(self, sample_submission, tmp_path):
        exporter = MarkdownExporter()
        out = tmp_path / "h1_test.md"
        md = exporter.export_submission_hackerone(sample_submission, out)
        assert out.exists()
        assert "Missing Content-Security-Policy" in md

    def test_export_submission_bugcrowd(self, sample_submission, tmp_path):
        exporter = MarkdownExporter()
        out = tmp_path / "bc_test.md"
        md = exporter.export_submission_bugcrowd(sample_submission, out)
        assert out.exists()

    def test_export_report(self, sample_submission, tmp_path):
        report = BountyReport(target="example.com", submissions=[sample_submission])
        exporter = MarkdownExporter()
        out = tmp_path / "report.md"
        md = exporter.export_report(report, out)
        assert out.exists()
        assert "Bug Bounty Report" in md


# --------------------------------------------------------------------------- #
# JSON Exporter Tests
# --------------------------------------------------------------------------- #

class TestJSONExporter:
    def test_export_submission(self, sample_submission, tmp_path):
        exporter = JSONExporter()
        out = tmp_path / "sub.json"
        data = exporter.export_submission(sample_submission, out)
        assert out.exists()
        assert data["title"] == "Missing Content-Security-Policy Header"

    def test_export_report(self, sample_submission, tmp_path):
        report = BountyReport(target="example.com", submissions=[sample_submission])
        exporter = JSONExporter()
        out = tmp_path / "report.json"
        data = exporter.export_report(report, out)
        assert out.exists()
        assert data["target"] == "example.com"
        assert len(data["submissions"]) == 1


# --------------------------------------------------------------------------- #
# HTML Exporter Tests
# --------------------------------------------------------------------------- #

class TestHTMLExporter:
    def test_export_report(self, sample_submission, tmp_path):
        report = BountyReport(target="example.com", submissions=[sample_submission])
        exporter = HTMLExporter()
        out = tmp_path / "report.html"
        html = exporter.export_report(report, out)
        assert out.exists()
        assert "Bug Bounty Report" in html
        assert "Missing Content-Security-Policy" in html


# --------------------------------------------------------------------------- #
# Report Index Tests
# --------------------------------------------------------------------------- #

class TestReportIndex:
    def test_build_empty(self):
        index = ReportIndex.build_index([])
        assert index["stats"]["total"] == 0
        assert index["top_10"] == []

    def test_build_with_submissions(self, sample_submission):
        index = ReportIndex.build_index([sample_submission])
        assert index["stats"]["total"] == 1
        assert index["stats"]["medium"] == 1
        assert len(index["top_10"]) == 1

    def test_export_index(self, tmp_path):
        index = ReportIndex.build_index([])
        out = tmp_path / "index.json"
        ReportIndex.export_index(index, out)
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["stats"]["total"] == 0

    def test_top_10_order(self, sample_submission):
        sub_critical = BountySubmission(title="Critical Finding", severity=BountySeverity.CRITICAL, priority=BountyPriority.P1)
        subs = [sample_submission, sub_critical]
        index = ReportIndex.build_index(subs)
        assert len(index["top_10"]) == 2
        assert index["top_10"][0]["title"] == "Critical Finding"


# --------------------------------------------------------------------------- #
# Engine Tests
# --------------------------------------------------------------------------- #

class TestHackerOneReportingEngine:
    def test_analyze_empty_project(self, empty_project_data, tmp_path):
        engine = HackerOneReportingEngine(tmp_path)
        report = engine.analyze_project(empty_project_data)
        assert report.submissions == []
        assert report.summary_stats["total"] == 0

    def test_analyze_with_findings(self, project_data_with_findings, tmp_path):
        engine = HackerOneReportingEngine(tmp_path)
        report = engine.analyze_project(project_data_with_findings)
        assert len(report.submissions) >= 2
        assert report.summary_stats["total"] >= 2

    def test_analyze_saves_outputs(self, project_data_with_findings, tmp_path):
        engine = HackerOneReportingEngine(tmp_path)
        engine.analyze_project(project_data_with_findings)
        assert (engine.bounty_dir / "bounty_report.json").exists()
        # The report is saved to reports/bounty/ which we can check

    def test_bounty_dir_created(self):
        engine = HackerOneReportingEngine(Path("."))
        assert engine.bounty_dir.exists()


# --------------------------------------------------------------------------- #
# Edge Cases Tests
# --------------------------------------------------------------------------- #

class TestEdgeCases:
    def test_submission_no_steps(self):
        sub = BountySubmission(title="Test", steps_to_reproduce=[])
        assert len(sub.steps_to_reproduce) == 0

    def test_submission_no_evidence(self):
        sub = BountySubmission(title="Test", evidence=[])
        assert len(sub.evidence) == 0

    def test_severity_all_mappings_consistent(self):
        mapper = SeverityMapper()
        for internal_sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            bounty = mapper.map_severity(internal_sev)
            priority = mapper.map_severity_to_priority(internal_sev)
            back = mapper.map_priority_to_severity(priority)
            assert bounty == back, f"Mismatch for {internal_sev}: {bounty} vs {back}"
